#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
db_builder.py — Rebuild SQLite index from Nessus exports (FULL RESET MODE, CORRECT FINDINGS)

Behavior:
- Deletes existing DB (if present) and rebuilds from scratch.
- Scans all .nessus/.nessus.gz files under input folder(s).
- Inserts one finding per (source, host, plugin) correctly.
- Restores FTS plugin_text table for GUI Expand functionality.

Usage:
  python db_builder.py --db nessus_index.db --in "C:\\Scans\\ThisWeek"
"""

import argparse
import gzip
import os
import sqlite3
import sys
from datetime import datetime, timezone
from glob import glob
from io import BytesIO
from lxml import etree

# -------------------------------------------------------
# SQLite Schema (matches GUI expectations, includes FTS)
# -------------------------------------------------------

SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE sources (
  source_id     INTEGER PRIMARY KEY,
  file_path     TEXT NOT NULL,
  file_name     TEXT NOT NULL,
  parsed_at_utc TEXT NOT NULL
);

CREATE TABLE plugins (
  plugin_id INTEGER PRIMARY KEY,
  name      TEXT,
  family    TEXT,
  severity  INTEGER
);

CREATE TABLE cves (
  cve_id TEXT PRIMARY KEY
);

CREATE TABLE plugin_cves (
  plugin_id INTEGER NOT NULL,
  cve_id    TEXT NOT NULL,
  PRIMARY KEY (plugin_id, cve_id),
  FOREIGN KEY (plugin_id) REFERENCES plugins(plugin_id) ON DELETE CASCADE,
  FOREIGN KEY (cve_id)    REFERENCES cves(cve_id)       ON DELETE CASCADE
);

CREATE TABLE hosts (
  host_id           INTEGER PRIMARY KEY,
  ip                TEXT,
  hostname          TEXT,
  os                TEXT,
  policy            TEXT,
  system_type       TEXT,
  credentialed_scan INTEGER DEFAULT 0
);

CREATE TABLE findings (
  finding_id    INTEGER PRIMARY KEY,
  source_id     INTEGER NOT NULL,
  host_id       INTEGER NOT NULL,
  plugin_id     INTEGER NOT NULL,
  port          INTEGER,
  protocol      TEXT,
  risk_factor   TEXT,
  severity      INTEGER,
  plugin_output TEXT,
  FOREIGN KEY (source_id) REFERENCES sources(source_id) ON DELETE CASCADE,
  FOREIGN KEY (host_id)   REFERENCES hosts(host_id)     ON DELETE CASCADE,
  FOREIGN KEY (plugin_id) REFERENCES plugins(plugin_id) ON DELETE CASCADE
);

CREATE VIRTUAL TABLE plugin_text
USING fts5(
  plugin_id UNINDEXED,
  name,
  synopsis,
  description,
  solution,
  family,
  cpe,
  fname,
  tokenize = 'unicode61'
);

CREATE INDEX idx_findings_host   ON findings(host_id);
CREATE INDEX idx_findings_plugin ON findings(plugin_id);
CREATE INDEX idx_findings_source ON findings(source_id);
CREATE INDEX idx_plugin_cves_cve ON plugin_cves(cve_id);
"""

def connect_db(db_path):
    if os.path.exists(db_path):
        os.remove(db_path)
    conn = sqlite3.connect(db_path)
    conn.executescript(SCHEMA)
    return conn


def _open_maybe_gz(path):
    if path.endswith(".gz"):
        with gzip.open(path, "rb") as f:
            return BytesIO(f.read())
    return open(path, "rb")


def _text(node):
    return (node.text or "").strip() if node is not None else None


# -------------------------------------------------------
# DB upserts
# -------------------------------------------------------

def upsert_plugin(conn, plugin_id, name, family, severity):
    conn.execute(
        "INSERT OR REPLACE INTO plugins(plugin_id, name, family, severity) VALUES (?, ?, ?, ?)",
        (plugin_id, name, family, severity)
    )


def upsert_plugin_text(conn, plugin_id, name, synopsis, description, solution, family, cpe_text, fname_text):
    conn.execute("DELETE FROM plugin_text WHERE plugin_id=?", (plugin_id,))
    conn.execute(
        "INSERT INTO plugin_text(plugin_id, name, synopsis, description, solution, family, cpe, fname) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (plugin_id, name or '', synopsis or '', description or '', solution or '',
         family or '', cpe_text or '', fname_text or '')
    )


def ensure_cve_mapping(conn, plugin_id, cve_list):
    for cve in cve_list:
        cve = cve.strip().upper()
        if not cve:
            continue
        conn.execute("INSERT OR IGNORE INTO cves(cve_id) VALUES (?)", (cve,))
        conn.execute("INSERT OR IGNORE INTO plugin_cves(plugin_id, cve_id) VALUES (?, ?)", (plugin_id, cve))


def get_or_create_host(conn, ip, hostname, os_name, policy, system_type, credentialed):
    cur = conn.execute(
        "SELECT host_id FROM hosts WHERE ip IS ? AND COALESCE(hostname,'') IS ?",
        (ip, hostname or '')
    )
    row = cur.fetchone()
    if row:
        return row[0]
    cur = conn.execute(
        "INSERT INTO hosts(ip, hostname, os, policy, system_type, credentialed_scan) VALUES (?, ?, ?, ?, ?, ?)",
        (ip, hostname, os_name, policy, system_type, 1 if credentialed else 0),
    )
    return cur.lastrowid


# -------------------------------------------------------
# **FIXED** Parsing Logic (Correct Findings Insertion)
# -------------------------------------------------------

def parse_nessus_into_db(conn, source_id, path):
    current_host_id = None
    host_tags = {}

    for event, elem in etree.iterparse(_open_maybe_gz(path), events=("start", "end")):
        tag = elem.tag

        # Entering a host block
        if event == "start" and tag.endswith("ReportHost"):
            current_host_id = None
            host_tags = {}

        elif event == "end" and tag.endswith("tag") and elem.get("name"):
            host_tags[elem.get("name")] = (elem.text or "").strip()

        elif event == "end" and tag.endswith("HostProperties"):
            ip = host_tags.get("host-ip") or host_tags.get("host.address")
            hostname = host_tags.get("host-fqdn") or host_tags.get("hostname")
            os_name = host_tags.get("os")
            policy = host_tags.get("policy-used")
            system_type = host_tags.get("system-type")
            cred = host_tags.get("Credentialed_Scan") or host_tags.get("credentialed_scan")
            credentialed = (str(cred).lower() == "true")
            ip = ip or hostname or "UNKNOWN"
            current_host_id = get_or_create_host(conn, ip, hostname, os_name, policy, system_type, credentialed)

        elif event == "end" and tag.endswith("ReportItem"):
            if current_host_id is None:
                elem.clear()
                continue

            attr = elem.attrib
            plugin_id = int(attr.get("pluginID", "0") or 0)
            port = int(attr.get("port", "0") or 0)
            protocol = attr.get("protocol")
            severity = int(attr.get("severity", "0") or 0)

            name = _text(elem.find("plugin_name")) or _text(elem.find("pluginName"))
            family = _text(elem.find("plugin_family")) or _text(elem.find("pluginFamily"))
            risk_factor = _text(elem.find("risk_factor"))
            plugin_output = _text(elem.find("plugin_output"))
            description = _text(elem.find("description"))
            synopsis = _text(elem.find("synopsis"))
            solution = _text(elem.find("solution"))
            cpe_text = " ".join([(_text(c) or "") for c in elem.findall("cpe") if _text(c)])
            fname_text = _text(elem.find("fname"))
            cves = [(c.text or "").strip().upper() for c in elem.findall("cve") if (c.text or "").strip()]

            upsert_plugin(conn, plugin_id, name, family, severity)
            ensure_cve_mapping(conn, plugin_id, cves)
            upsert_plugin_text(conn, plugin_id, name, synopsis, description, solution, family, cpe_text, fname_text)

            conn.execute(
                "INSERT INTO findings(source_id, host_id, plugin_id, port, protocol, risk_factor, severity, plugin_output)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (source_id, current_host_id, plugin_id, port, protocol, risk_factor, severity, plugin_output),
            )

            elem.clear()

        elif event == "end" and tag.endswith("ReportHost"):
            elem.clear()

    conn.commit()


# -------------------------------------------------------
# File Discovery & Master Build
# -------------------------------------------------------

def find_nessus_files(path_list):
    out = []
    for p in path_list:
        if os.path.isdir(p):
            for root, _, files in os.walk(p):
                for f in files:
                    if f.endswith(".nessus") or f.endswith(".nessus.gz"):
                        out.append(os.path.join(root, f))
        else:
            for f in glob(p):
                if f.endswith(".nessus") or f.endswith(".nessus.gz"):
                    out.append(f)
    return sorted(set(out))


def build_database(db_path, inputs):
    conn = connect_db(db_path)
    files = find_nessus_files(inputs)
    if not files:
        conn.close()
        raise SystemExit("No scan files found.")

    for path in files:
        conn.execute(
            "INSERT INTO sources(file_path, file_name, parsed_at_utc) VALUES (?, ?, ?)",
            (os.path.abspath(path), os.path.basename(path), datetime.now(timezone.utc).isoformat()),
        )
        sid = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        parse_nessus_into_db(conn, sid, path)

    conn.execute("VACUUM")
    conn.close()
    print(f"\n✅ Rebuild complete — {len(files)} scan file(s) indexed.\n")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", required=True)
    ap.add_argument("--in", dest="inputs", nargs="+", required=True)
    args = ap.parse_args()
    build_database(args.db, args.inputs)


if __name__ == "__main__":
    sys.exit(main())
