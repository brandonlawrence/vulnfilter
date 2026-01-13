#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VulnFilter — GUI to filter .nessus files without touching originals.

Locked decisions for this build:
- DB is the source of truth for Expand (no XML fallback)
- Expand works even if no scan file/folder is selected
- Filtering / Export logic remains as-is (still edits selected .nessus/.gz)
- DB schema matches db_builder.py:
  * plugins(plugin_id INTEGER PRIMARY KEY, name TEXT, family TEXT, severity INTEGER)
  * plugin_cves(plugin_id INTEGER, cve_id TEXT)
  * plugin_text(plugin_id INTEGER, name TEXT) -- FTS5 if available

NEW FEATURE (this update)
- Mode toggle:
    * Drop mode (current behavior): removes/edits based on lists/rules.
    * Include-only mode: ONLY keep data that matches CVEs OR Plugin IDs OR Name/CPE rules
      (and optionally only keep hosts matching Endpoints).

NEW FEATURE (this update)
- Quick host list popup (after Export Filtered):
    * Shows hosts per exported file
    * Includes findings count per host
    * Copy-to-clipboard button
    * "View Last Hosts" button to re-open the last list

No external dependencies: Python stdlib only.
"""

import os, re, fnmatch, json, sqlite3, ipaddress, time, threading, subprocess, sys, gzip
import xml.etree.ElementTree as ET
import tkinter as tk
from tkinter import ttk, messagebox, filedialog

# ---------------- Base paths ----------------
BASE_DIR     = os.path.dirname(os.path.abspath(__file__))
PRESETS_DIR  = os.path.join(BASE_DIR, "presets")
OUTPUT_DIR   = os.path.join(BASE_DIR, "output")
LOG_DIR      = os.path.join(BASE_DIR, "logs")
SCAN_DIRS    = []  # user will browse to a OneDrive or wherever
DB_PATH      = os.path.join(BASE_DIR, "nessus_index.db")

for d in (PRESETS_DIR, OUTPUT_DIR, LOG_DIR, *SCAN_DIRS):
    os.makedirs(d, exist_ok=True)

# ---------------- Session state ----------------
SESSION_BLACKLIST_CVES   = set()
SESSION_BLACKLIST_PIDS   = set()
LAST_KEYWORD             = None
SESSION_NAMECPE_PATTERNS = []   # list[str] (raw patterns, persisted in profile)
LAST_RUN_DETAILS         = []   # list[str] for on-screen popup
LAST_LOG_PATH            = None

LAST_HOST_LIST_TEXT      = ""   # quick list popup (export only)

# ---------------- Helpers ----------------
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
CVE_TOKEN_RE = re.compile(r"(?i)\bCVE-\d{4}-\d{4,}\b")
WORD_CVE_RE = CVE_TOKEN_RE

# Broad family regexes for common noisy buckets

# --- .NET / ASP.NET ---
DEFAULT_DOTNET_RE = (
    r"(?i)("
    r"\b\.net\b|"
    r"\basp\.?net\b|"
    r"\baspnetcore\b|"
    r"\bmicrosoft\.aspnetcore\b|"
    r"\bnet\s*core\b|"
    r"\bnet\s*framework\b|"
    r"microsoft:asp\.?net|"
    r"microsoft:\.?net|"
    r"microsoft:dotnet"
    r")"
)

# --- Adobe Flash (legacy but still noisy in scans) ---
DEFAULT_FLASH_RE = (
    r"(?i)("
    r"\bflash\b|"
    r"\badobe\s*flash\b|"
    r"\bshockwave\s*flash\b|"
    r"cpe:/a:adobe:flash_player|"
    r"adobe:flash_player"
    r")"
)

# --- Log4j / Log4Shell ---
DEFAULT_LOG4J_RE = (
    r"(?i)("
    r"\blog4j\b|"
    r"\borg\.apache\.logging\.log4j\b|"
    r"cpe:/a:apache:log4j|"
    r"apache:log4j"
    r")"
)

# --- Java / JVM ecosystem ---
DEFAULT_JAVA_RE = (
    r"(?i)("
    r"\bjava\b|"
    r"\bjre\b|"
    r"\bjdk\b|"
    r"\bjvm\b|"
    r"\boracle\s*java\b|"
    r"\bopenjdk\b|"
    r"cpe:/a:oracle:java|"
    r"cpe:/a:openjdk:openjdk"
    r")"
)

# --- Apache HTTP / core Apache ---
DEFAULT_APACHE_RE = (
    r"(?i)("
    r"\bapache\b|"
    r"\bhttpd\b|"
    r"\bapache\s*http\b|"
    r"cpe:/a:apache:http_server|"
    r"apache:http_server"
    r")"
)

# --- OpenSSL / crypto libs ---
DEFAULT_OPENSSL_RE = (
    r"(?i)("
    r"\bopenssl\b|"
    r"\blibssl\b|"
    r"\blibcrypto\b|"
    r"cpe:/a:openssl:openssl"
    r")"
)

# --- PHP ecosystem ---
DEFAULT_PHP_RE = (
    r"(?i)("
    r"\bphp\b|"
    r"\bphp-fpm\b|"
    r"\bphp\s*extension\b|"
    r"cpe:/a:php:php"
    r")"
)

# --- Python runtime / packages ---
DEFAULT_PYTHON_RE = (
    r"(?i)("
    r"\bpython\b|"
    r"\bpython2\b|"
    r"\bpython3\b|"
    r"\bpip\b|"
    r"\bpypi\b|"
    r"cpe:/a:python:python"
    r")"
)

# --- Node.js / JavaScript runtime ---
DEFAULT_NODE_RE = (
    r"(?i)("
    r"\bnode\.?js\b|"
    r"\bnodejs\b|"
    r"\bnpm\b|"
    r"\byarn\b|"
    r"cpe:/a:nodejs:node\.?js"
    r")"
)

# --- Windows OS / core components ---
DEFAULT_WINDOWS_RE = (
    r"(?i)("
    r"\bwindows\b|"
    r"\bmicrosoft\s*windows\b|"
    r"\bwin32\b|"
    r"\bwin64\b|"
    r"cpe:/o:microsoft:windows"
    r")"
)

# --- Microsoft Visual C++ runtimes ---
DEFAULT_MSVC_RE = (
    r"(?i)("
    r"\bvisual\s*c\+\+\b|"
    r"\bmsvc\b|"
    r"\bvcredist\b|"
    r"\bmicrosoft\s*vc\+\+\b"
    r")"
)

# --- Linux kernel / glibc ---
DEFAULT_LINUX_KERNEL_RE = (
    r"(?i)("
    r"\blinux\s*kernel\b|"
    r"\bkernel\b|"
    r"\bglibc\b|"
    r"cpe:/o:linux:linux_kernel"
    r")"
)

# --- Databases ---
DEFAULT_DB_RE = (
    r"(?i)("
    r"\bmysql\b|"
    r"\bpostgresql\b|"
    r"\bpostgres\b|"
    r"\bmariadb\b|"
    r"\boracle\s*database\b|"
    r"\bmssql\b|"
    r"\bsql\s*server\b"
    r")"
)

# --- Smart family keyword → regex map ---
SMART_FAMILY_MAP = {
    # .NET
    ".net": DEFAULT_DOTNET_RE,
    "dotnet": DEFAULT_DOTNET_RE,
    "asp.net": DEFAULT_DOTNET_RE,
    "aspnet": DEFAULT_DOTNET_RE,
    "aspnetcore": DEFAULT_DOTNET_RE,
    "net core": DEFAULT_DOTNET_RE,
    "net framework": DEFAULT_DOTNET_RE,

    # Flash
    "flash": DEFAULT_FLASH_RE,
    "adobe flash": DEFAULT_FLASH_RE,
    "shockwave": DEFAULT_FLASH_RE,

    # Log4j
    "log4j": DEFAULT_LOG4J_RE,
    "log4shell": DEFAULT_LOG4J_RE,
    "apache log4j": DEFAULT_LOG4J_RE,

    # Java
    "java": DEFAULT_JAVA_RE,
    "jdk": DEFAULT_JAVA_RE,
    "jre": DEFAULT_JAVA_RE,
    "openjdk": DEFAULT_JAVA_RE,

    # Apache
    "apache": DEFAULT_APACHE_RE,
    "httpd": DEFAULT_APACHE_RE,

    # OpenSSL
    "openssl": DEFAULT_OPENSSL_RE,
    "ssl": DEFAULT_OPENSSL_RE,
    "crypto": DEFAULT_OPENSSL_RE,

    # PHP
    "php": DEFAULT_PHP_RE,

    # Python
    "python": DEFAULT_PYTHON_RE,
    "pip": DEFAULT_PYTHON_RE,

    # Node.js
    "node": DEFAULT_NODE_RE,
    "nodejs": DEFAULT_NODE_RE,
    "npm": DEFAULT_NODE_RE,

    # Windows
    "windows": DEFAULT_WINDOWS_RE,
    "microsoft windows": DEFAULT_WINDOWS_RE,

    # MSVC
    "visual c++": DEFAULT_MSVC_RE,
    "vcredist": DEFAULT_MSVC_RE,

    # Linux
    "linux kernel": DEFAULT_LINUX_KERNEL_RE,
    "kernel": DEFAULT_LINUX_KERNEL_RE,

    # Databases
    "database": DEFAULT_DB_RE,
    "mysql": DEFAULT_DB_RE,
    "postgres": DEFAULT_DB_RE,
}

def _txt(elem):
    return (elem.text or "").strip() if elem is not None else ""

def host_ids_from_reporthost(host_elem):
    """Return list of identifiers we can match the host by."""
    ids = []
    name_attr = host_elem.get("name") or ""
    if name_attr:
        ids.append(name_attr)
    props = host_elem.find("HostProperties")
    if props is not None:
        tags = { (t.get("name") or ""): _txt(t) for t in props.findall("tag") }
        for k in ("host-fqdn","hostname","netbios-name","host-ip"):
            v = tags.get(k, "")
            if v:
                ids.append(v)
    seen, out = set(), []
    for i in ids:
        if i not in seen:
            out.append(i); seen.add(i)
    return out

def is_ip_string(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except Exception:
        return False

def in_any_cidr(ip_str: str, cidr_list):
    try:
        ip = ipaddress.ip_address(ip_str)
    except Exception:
        return False
    for c in cidr_list:
        try:
            net = ipaddress.ip_network(c, strict=False)
        except Exception:
            continue
        if ip in net:
            return True
    return False

def endpoint_matches(patterns, value, mode):
    """
    patterns: list of strings OR compiled regex objects (if mode == 'regex')
    value: host identifier (hostname or IP)
    - Supports CIDRs when value is an IP and pattern contains '/'
    """
    if not patterns:
        return False

    if is_ip_string(value):
        cidrs = [p for p in patterns if isinstance(p, str) and '/' in p]
        if cidrs and in_any_cidr(value, cidrs):
            return True

    if mode == "regex":
        return any(p.search(value) for p in patterns)
    if mode == "glob":
        return any(fnmatch.fnmatch(value, p) for p in patterns)
    return value in patterns

def reportitem_has_plugin(ri, pid_set):
    """True if this ReportItem's pluginID is in the provided set."""
    if not pid_set:
        return False
    pid = ri.get("pluginID")
    return pid is not None and pid.isdigit() and (int(pid) in pid_set)

def prepare_endpoint_patterns(raw_patterns, mode):
    """Validate and normalize endpoint patterns for endpoint_matches."""
    if not raw_patterns:
        return []
    if mode == "regex":
        compiled = []
        for p in raw_patterns:
            try:
                compiled.append(re.compile(p))
            except re.error as e:
                raise ValueError(f"Bad regex: {p} -> {e}")
        return compiled
    out = []
    for p in raw_patterns:
        p = p.strip()
        if not p:
            continue
        if '/' in p:
            try:
                ipaddress.ip_network(p, strict=False)
                out.append(p)
            except Exception:
                raise ValueError(f"Invalid CIDR pattern: {p}")
        else:
            out.append(p)
    return out

def prepare_namecpe_patterns(raw_patterns):
    """Compile regexes for pluginName/family/fname/CPE ONLY (case-insensitive)."""
    out = []
    for p in raw_patterns or []:
        p = p.strip()
        if not p:
            continue
        try:
            out.append(re.compile(p, re.IGNORECASE))
        except re.error as e:
            raise ValueError(f"Bad name/CPE regex: {p} -> {e}")
    return out

def reportitem_namecpe_matches(ri: ET.Element, compiled_patterns) -> bool:
    """Title/family/short-name/CPE only (avoid long-text evidence)."""
    if not compiled_patterns:
        return False
    hay = []
    hay.append(ri.get("pluginName") or "")
    hay.append(ri.get("pluginFamily") or "")
    for tag in ("plugin_name","plugin_family","fname"):
        el = ri.find(tag)
        if el is not None and el.text:
            hay.append(el.text)
    for c in ri.findall("cpe"):
        if c is not None and c.text:
            hay.append(c.text)
    blob = " ".join(hay)
    return any(rx.search(blob) for rx in compiled_patterns)

def collect_cves_from_text(s: str):
    """Return normalized CVE tokens found in text."""
    return [m.group(0).upper() for m in WORD_CVE_RE.finditer(s or "")]

def split_cve_blob(blob: str):
    """Split CVE tag text which may be comma/space/semicolon separated."""
    if not blob:
        return []
    parts = re.split(r"[,\s;]+", blob.strip())
    return [p.upper() for p in parts if CVE_RE.match(p.strip())]

def join_cves(cves):
    return ", ".join(sorted({c.upper() for c in cves}))

def has_meaningful_text(s: str) -> bool:
    if not s:
        return False
    t = re.sub(r"[\s•\-\*\u2022]+", "", s, flags=re.MULTILINE)
    return any(ch.isalnum() for ch in t)

# -------- File I/O helpers (gzip-aware) --------
def is_gz(path: str) -> bool:
    return path.lower().endswith(".nessus.gz") or path.lower().endswith(".gz")

def parse_nessus_tree(path: str) -> ET.ElementTree:
    if is_gz(path):
        with gzip.open(path, "rt", encoding="utf-8", errors="ignore") as fh:
            return ET.parse(fh)
    return ET.parse(path)

def write_nessus_tree(tree: ET.ElementTree, out_path: str):
    xml_bytes = ET.tostring(tree.getroot(), encoding="utf-8", xml_declaration=True)
    if out_path.lower().endswith(".gz"):
        with gzip.open(out_path, "wb") as gz:
            gz.write(xml_bytes)
    else:
        with open(out_path, "wb") as fh:
            fh.write(xml_bytes)

def split_nessus_basename(filename: str):
    """
    Returns (stem_without_nessus_ext, ext) where ext is '.nessus' or '.nessus.gz' (or generic fallback).
    """
    lower = filename.lower()
    if lower.endswith(".nessus.gz"):
        return filename[:-11], ".nessus.gz"
    if lower.endswith(".nessus"):
        return filename[:-7], ".nessus"
    if lower.endswith(".gz"):
        base = filename[:-3]
        return base, ".gz"
    root, ext = os.path.splitext(filename)
    return root, ext or ".nessus"

def make_output_path(infile: str):
    base = os.path.basename(infile)
    stem, ext = split_nessus_basename(base)
    if ext == ".nessus":
        return os.path.join(OUTPUT_DIR, f"{stem}.filtered.nessus")
    if ext == ".nessus.gz":
        return os.path.join(OUTPUT_DIR, f"{stem}.filtered.nessus.gz")
    return os.path.join(OUTPUT_DIR, f"{stem}.filtered{ext}")

# ---------------- Surgical editors ----------------
def edit_reportitem_surgical(ri: ET.Element, drop_cves: set) -> dict:
    metrics = {
        'cves_removed': 0,
        'desc_lines_removed': 0,
        'po_lines_removed': 0,
        'cvss_source_retargeted': False,
        'cves_remaining': 0,
        'item_became_empty': False,
    }
    remaining_cves = []
    for cve_el in list(ri.findall("cve")):
        existing = split_cve_blob(_txt(cve_el))
        keep = [c for c in existing if c not in drop_cves]
        removed_here = len(existing) - len(keep)
        metrics['cves_removed'] += removed_here
        if keep:
            cve_el.text = join_cves(keep)
            remaining_cves.extend(keep)
        else:
            ri.remove(cve_el)

    remaining_cves = sorted(set(remaining_cves))
    metrics['cves_remaining'] = len(remaining_cves)

    desc_el = ri.find("description")
    if desc_el is not None and desc_el.text:
        lines = desc_el.text.splitlines(True)
        keep, removed = [], 0
        for ln in lines:
            ln_cves = set(collect_cves_from_text(ln))
            if ln_cves & drop_cves:
                removed += 1
            else:
                keep.append(ln)
        if removed:
            desc_el.text = "".join(keep).strip()
            metrics['desc_lines_removed'] += removed

    po = ri.find("plugin_output")
    if po is not None and po.text:
        lines = po.text.splitlines(True)
        keep, removed = [], 0
        for ln in lines:
            ln_cves = set(collect_cves_from_text(ln))
            if ln_cves & drop_cves:
                removed += 1
            else:
                keep.append(ln)
        if removed:
            po.text = "".join(keep)
            metrics['po_lines_removed'] += removed

    cvss_src = ri.find("cvss_score_source")
    if cvss_src is not None:
        raw = (_txt(cvss_src)).upper()
        pointed = collect_cves_from_text(raw)
        if any(c in drop_cves for c in pointed):
            cvss_src.text = (remaining_cves[0] if remaining_cves else "")
            metrics['cvss_source_retargeted'] = True

    if metrics['cves_remaining'] == 0:
        meaningful_bits = []
        if desc_el is not None and has_meaningful_text(desc_el.text):
            meaningful_bits.append("desc")
        if po is not None and has_meaningful_text(po.text):
            meaningful_bits.append("po")
        metrics['item_became_empty'] = (len(meaningful_bits) == 0)

    return metrics

def edit_host_patch_summary_surgical(host: ET.Element, drop_cves: set) -> dict:
    removed_total = 0
    adjusted_tags = 0
    hp = host.find("HostProperties")
    if hp is None:
        return {'patch_cves_removed': 0, 'patch_num_adjusted': 0}
    tags = { (t.get("name") or ""): t for t in hp.findall("tag") }
    cves_removed_by_suffix = {}
    for name, tag in list(tags.items()):
        if not name.startswith("patch-summary-cves"):
            continue
        suffix = name[len("patch-summary-cves"):]
        items = [tok.strip().upper() for tok in re.split(r"[,\s]+", (tag.text or "")) if tok.strip()]
        keep = [c for c in items if not CVE_RE.match(c) or c not in drop_cves]
        removed_here = len(items) - len(keep)
        if removed_here:
            tag.text = ", ".join(keep)
            removed_total += removed_here
            cves_removed_by_suffix[suffix] = cves_removed_by_suffix.get(suffix, 0) + removed_here
            adjusted_tags += 1
    for name, tag in list(tags.items()):
        if not name.startswith("patch-summary-cve-num"):
            continue
        suffix = name[len("patch-summary-cve-num"):]
        try:
            n = int((tag.text or "0").strip())
        except:
            continue
        drop_n = cves_removed_by_suffix.get(suffix, 0)
        if drop_n:
            new_n = max(0, n - drop_n)
            tag.text = str(new_n)
            adjusted_tags += 1
    return {'patch_cves_removed': removed_total, 'patch_num_adjusted': adjusted_tags}

def strip_pluginset_ids(root: ET.Element, drop_pids: set) -> int:
    removed = 0
    for pref in root.findall(".//preference"):
        name_txt = (pref.findtext("name") or "").strip().lower()
        if name_txt != "plugin_set":
            continue
        val_el = pref.find("value")
        if val_el is None:
            continue
        raw = (val_el.text or "").strip()
        if not raw:
            continue
        parts = [t for t in re.split(r"[;,\s]+", raw) if t]
        keep = []
        for tok in parts:
            if tok.isdigit() and int(tok) in drop_pids:
                removed += 1
                continue
            keep.append(tok)
        val_el.text = ";".join(keep)
    return removed

def keep_only_pluginset_ids(root: ET.Element, keep_pids: set) -> int:
    """
    Include-only mode helper: if plugin_set exists, keep only the plugin IDs in keep_pids.
    Returns number removed from the preference list.
    """
    if not keep_pids:
        return 0
    removed = 0
    for pref in root.findall(".//preference"):
        name_txt = (pref.findtext("name") or "").strip().lower()
        if name_txt != "plugin_set":
            continue
        val_el = pref.find("value")
        if val_el is None:
            continue
        raw = (val_el.text or "").strip()
        if not raw:
            continue
        parts = [t for t in re.split(r"[;,\s]+", raw) if t]
        keep = []
        for tok in parts:
            if tok.isdigit():
                if int(tok) in keep_pids:
                    keep.append(tok)
                else:
                    removed += 1
            else:
                keep.append(tok)
        val_el.text = ";".join(keep)
    return removed

# ---------------- Include-only match helpers ----------------
def reportitem_collect_all_cves(ri: ET.Element) -> set:
    """
    Collect CVEs from:
      - <cve> tags
      - cvss_score_source
      - description/plugin_output text tokens (only CVE tokens)
    """
    found = set()

    for cve_el in ri.findall("cve"):
        for c in split_cve_blob(_txt(cve_el)):
            if c:
                found.add(c.upper())

    cvss_src = ri.find("cvss_score_source")
    if cvss_src is not None and (cvss_src.text or "").strip():
        for c in collect_cves_from_text(cvss_src.text):
            found.add(c.upper())

    desc_el = ri.find("description")
    if desc_el is not None and desc_el.text:
        for c in collect_cves_from_text(desc_el.text):
            found.add(c.upper())

    po = ri.find("plugin_output")
    if po is not None and po.text:
        for c in collect_cves_from_text(po.text):
            found.add(c.upper())

    return found

def reportitem_matches_include(ri: ET.Element, include_cves: set, include_pids: set, include_namecpe_patterns) -> bool:
    """
    OR-semantics:
      - pluginID in include_pids
      - any CVE in include_cves
      - name/cpe rule matches
    If none of the include criteria are provided, returns True (caller should prevent that in UI).
    """
    pid = ri.get("pluginID") or ""
    if include_pids and pid.isdigit() and int(pid) in include_pids:
        return True

    if include_namecpe_patterns and reportitem_namecpe_matches(ri, include_namecpe_patterns):
        return True

    if include_cves:
        found = reportitem_collect_all_cves(ri)
        if found & include_cves:
            return True

    if not include_cves and not include_pids and not include_namecpe_patterns:
        return True

    return False

# ---------------- Filtering core ----------------
def filter_nessus(infile, cves_list, pids_set, endpoints, ep_mode,
                  prune_empty, namecpe_patterns_compiled, dry_run=True, mode="drop"):
    """
    mode:
      - "drop": current behavior (drop hosts/items, surgical CVE edits)
      - "include": keep only matches for CVEs OR PIDs OR Name/CPE rules (and optionally endpoints)

    Returns (summary_str, tree or None, removed_counts_dict)
    Also appends verbose details to LAST_RUN_DETAILS.
    """
    tree = parse_nessus_tree(infile)
    root = tree.getroot()
    report = root.find("Report")
    if report is None:
        raise RuntimeError("Malformed .nessus (no <Report> element)")

    hosts_removed = 0
    items_removed = 0
    removed_by_host = {}

    tot_cve_tags_removed = 0
    tot_desc_lines_removed = 0
    tot_po_lines_removed = 0
    tot_cvss_retarget = 0
    tot_patch_cves_removed = 0

    cves_norm = set(c.upper() for c in (cves_list or []))
    pids_norm = set(pids_set or set())
    mode = (mode or "drop").strip().lower()

    LAST_RUN_DETAILS.append(f"# File: {infile}")
    LAST_RUN_DETAILS.append(f"# Started: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    LAST_RUN_DETAILS.append(f"# Mode: {mode}")
    LAST_RUN_DETAILS.append("")

    include_cves = cves_norm if mode == "include" else set()
    include_pids = pids_norm if mode == "include" else set()
    include_namecpe = namecpe_patterns_compiled if mode == "include" else []

    drop_cves = cves_norm if mode == "drop" else set()
    drop_pids = pids_norm if mode == "drop" else set()
    drop_namecpe = namecpe_patterns_compiled if mode == "drop" else []

    for host in list(report.findall("ReportHost")):
        hids = host_ids_from_reporthost(host)
        host_disp = hids[0] if hids else (host.get("name") or "(unnamed)")

        if endpoints:
            matched = any(endpoint_matches(endpoints, hid, ep_mode) for hid in hids)
            if mode == "drop":
                if matched:
                    if not dry_run:
                        report.remove(host)
                    hosts_removed += 1
                    LAST_RUN_DETAILS.append(f"HOST REMOVED (endpoint match): {host_disp}")
                    continue
            else:
                if not matched:
                    if not dry_run:
                        report.remove(host)
                    hosts_removed += 1
                    LAST_RUN_DETAILS.append(f"HOST REMOVED (did not match include endpoints): {host_disp}")
                    continue

        if mode == "drop" and (not dry_run) and drop_cves:
            ps = edit_host_patch_summary_surgical(host, drop_cves)
            tot_patch_cves_removed += ps.get('patch_cves_removed', 0)
            if ps.get('patch_cves_removed', 0):
                LAST_RUN_DETAILS.append(f"Host {host_disp}: patch-summary CVEs removed: {ps['patch_cves_removed']}")

        removed_items_this_host = 0
        for ri in list(host.findall("ReportItem")):
            pid = ri.get("pluginID") or ""
            pname = ri.get("pluginName") or ""

            if mode == "include":
                if not reportitem_matches_include(ri, include_cves, include_pids, include_namecpe):
                    removed_items_this_host += 1
                    if not dry_run:
                        host.remove(ri)
                    LAST_RUN_DETAILS.append(
                        f"  ITEM REMOVED [{host_disp}] PID={pid} Name={pname!r} — did not match include criteria"
                    )
                continue

            reason = None
            if reportitem_has_plugin(ri, drop_pids):
                reason = f"pluginID in drop list ({pid})"
            elif reportitem_namecpe_matches(ri, drop_namecpe):
                reason = "name/CPE rule"

            if reason:
                removed_items_this_host += 1
                if not dry_run:
                    host.remove(ri)
                LAST_RUN_DETAILS.append(f"  ITEM REMOVED [{host_disp}] PID={pid} Name={pname!r} — {reason}")
                continue

            if drop_cves and not dry_run:
                m = edit_reportitem_surgical(ri, drop_cves)
                tot_cve_tags_removed   += m['cves_removed']
                tot_desc_lines_removed += m['desc_lines_removed']
                tot_po_lines_removed   += m['po_lines_removed']
                if m['cvss_source_retargeted']:
                    tot_cvss_retarget += 1
                if m['cves_removed'] or m['desc_lines_removed'] or m['po_lines_removed']:
                    LAST_RUN_DETAILS.append(
                        f"  ITEM EDIT [{host_disp}] PID={pid} Name={pname!r} "
                        f"(CVE tags -{m['cves_removed']}, desc lines -{m['desc_lines_removed']}, po lines -{m['po_lines_removed']})"
                    )
                if m['item_became_empty']:
                    host.remove(ri)
                    removed_items_this_host += 1
                    LAST_RUN_DETAILS.append(f"  ITEM REMOVED [{host_disp}] PID={pid} Name={pname!r} — after surgical edits, became empty")

        if removed_items_this_host:
            items_removed += removed_items_this_host
            removed_by_host[host_disp] = removed_items_this_host

        if prune_empty and not dry_run:
            if len(host.findall("ReportItem")) == 0:
                report.remove(host)
                hosts_removed += 1
                LAST_RUN_DETAILS.append(f"HOST PRUNED (0 findings after processing): {host_disp}")

    remaining_hosts = len(report.findall("ReportHost"))

    lines = [
        "=== VulnFilter summary ===",
        f"Mode: {mode}",
        f"Remaining hosts in memory: {remaining_hosts}",
        f"Removed hosts: {hosts_removed}",
        f"Removed findings: {items_removed}",
    ]

    if mode == "drop" and (not dry_run) and any([tot_cve_tags_removed, tot_desc_lines_removed, tot_po_lines_removed, tot_cvss_retarget, tot_patch_cves_removed]):
        lines += [
            "",
            "Surgical edits:",
            f"  CVE tags removed: {tot_cve_tags_removed}",
            f"  description lines removed: {tot_desc_lines_removed}",
            f"  plugin_output lines removed: {tot_po_lines_removed}",
            f"  cvss_score_source retargeted: {tot_cvss_retarget}",
            f"  patch-summary CVEs removed (host): {tot_patch_cves_removed}",
        ]

    if removed_by_host:
        lines.append("\nTop hosts by removed items:")
        for h, n in sorted(removed_by_host.items(), key=lambda kv: kv[1], reverse=True)[:10]:
            lines.append(f"  {h}: {n}")

    LAST_RUN_DETAILS.append("")
    LAST_RUN_DETAILS.append("\n".join(lines))
    LAST_RUN_DETAILS.append("")

    return "\n".join(lines), (None if dry_run else tree), {
        "remaining_hosts": remaining_hosts,
        "hosts_removed": hosts_removed,
        "items_removed": items_removed,
    }

# ---------------- DB (ONLY) search ----------------
def db_available() -> bool:
    return os.path.exists(DB_PATH) and os.path.isfile(DB_PATH)

def db_find_cves_and_plugins(keyword, db_path=DB_PATH, limit=5000):
    """
    Return (set_of_cves, list_of_plugins) where list_of_plugins=[(plugin_id, name)].
    Uses FTS (plugin_text) first, then LIKE. Includes plugins that have NO CVEs.
    Applies session blacklist.
    """
    if not keyword or not db_available():
        return set(), []

    q = keyword.strip()
    cves, plugins = set(), []

    con = sqlite3.connect(db_path); cur = con.cursor()
    try:
        if CVE_RE.match(q):
            cvu = q.upper()
            if cvu not in SESSION_BLACKLIST_CVES:
                cves.add(cvu)
            return cves, plugins

        if q.isdigit():
            pid = int(q)
            if pid not in SESSION_BLACKLIST_PIDS:
                cur.execute("SELECT name FROM plugins WHERE plugin_id=?", (pid,))
                row = cur.fetchone()
                if row:
                    plugins.append((pid, row[0] or ""))
                    cur.execute("SELECT cve_id FROM plugin_cves WHERE plugin_id=? LIMIT ?", (pid, limit))
                    for (c,) in cur.fetchall():
                        if c and c.upper() not in SESSION_BLACKLIST_CVES:
                            cves.add(c.upper())
            return cves, plugins

        plugin_ids = []
        try:
            fts_q = " ".join(t for t in re.split(r"\s+", q) if t)
            cur.execute("""
                SELECT p.plugin_id
                FROM plugin_text ft
                JOIN plugins p USING(plugin_id)
                WHERE ft MATCH ?
                LIMIT ?;
            """, (fts_q, limit))
            plugin_ids = [r[0] for r in cur.fetchall()]
        except sqlite3.OperationalError:
            plugin_ids = []

        if not plugin_ids:
            cur.execute("""
                SELECT plugin_id FROM plugins
                WHERE name LIKE ? OR family LIKE ?
                LIMIT ?;
            """, (f"%{q}%", f"%{q}%", limit))
            plugin_ids = [r[0] for r in cur.fetchall()]

        if not plugin_ids:
            return cves, plugins

        plugin_ids = [pid for pid in plugin_ids if pid not in SESSION_BLACKLIST_PIDS]
        if not plugin_ids:
            return cves, plugins

        ph = ",".join("?"*len(plugin_ids))
        cur.execute(f"SELECT plugin_id, name FROM plugins WHERE plugin_id IN ({ph})", plugin_ids)
        id_to_name = {pid: (nm or "") for pid, nm in cur.fetchall()}

        cur.execute(f"SELECT plugin_id, cve_id FROM plugin_cves WHERE plugin_id IN ({ph}) LIMIT ?",
                    (*plugin_ids, limit))
        seen_with_cve = set()
        for pid, c in cur.fetchall():
            if not c:
                continue
            cu = c.upper()
            if cu in SESSION_BLACKLIST_CVES:
                continue
            cves.add(cu)
            seen_with_cve.add(pid)

        for pid in plugin_ids:
            if pid not in seen_with_cve:
                plugins.append((pid, id_to_name.get(pid, "")))

        return cves, plugins
    finally:
        try: con.close()
        except: pass

def db_guess_cve_titles(cves, db_path=DB_PATH):
    if not cves or not db_available():
        return {}
    titles = {}
    con = sqlite3.connect(db_path)
    cur = con.cursor()
    try:
        ph = ",".join("?" * len(cves))
        cur.execute(f"""
            SELECT pc.cve_id, COALESCE(pt.name, p.name, '')
            FROM plugin_cves pc
            LEFT JOIN plugins p      ON p.plugin_id = pc.plugin_id
            LEFT JOIN plugin_text pt ON pt.plugin_id = pc.plugin_id
            WHERE pc.cve_id IN ({ph})
        """, [c.upper() for c in cves])
        from collections import Counter, defaultdict
        bucket = defaultdict(list)
        for cve, nm in cur.fetchall():
            nm = (nm or '').strip()
            if nm:
                bucket[cve.upper()].append(nm)
        for cve, names in bucket.items():
            cnt = Counter(names)
            common = [n for n, _ in cnt.most_common()]
            common.sort(key=lambda s: (len(s) > 12, len(s)))
            titles[cve] = common[0]
        return titles
    finally:
        try: con.close()
        except: pass

# --------- Discovery helpers ----------
def find_nessus_files(paths):
    """Return a sorted unique list of .nessus/.nessus.gz files under path(s)."""
    exts = (".nessus", ".nessus.gz")
    found = []
    for p in ([paths] if isinstance(paths, str) else paths):
        if not p:
            continue
        if os.path.isdir(p):
            for root, _, files in os.walk(p):
                for f in files:
                    low = f.lower()
                    if low.endswith(exts):
                        found.append(os.path.join(root, f))
        elif os.path.isfile(p):
            low = p.lower()
            if low.endswith(exts):
                found.append(p)
    return sorted(set(found))

def resolve_targets(selection_path: str):
    if not selection_path:
        return []
    if os.path.isdir(selection_path):
        return find_nessus_files(selection_path)
    return [selection_path] if os.path.isfile(selection_path) else []

# ---------------- Profiles ----------------
def list_profiles():
    return sorted([f[:-5] for f in os.listdir(PRESETS_DIR) if f.endswith(".json")])

def save_profile(name, data: dict):
    if not name.strip():
        raise ValueError("Profile name is required.")
    path = os.path.join(PRESETS_DIR, f"{name}.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)

def load_profile(name):
    path = os.path.join(PRESETS_DIR, f"{name}.json")
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)

def delete_profile(name):
    path = os.path.join(PRESETS_DIR, f"{name}.json")
    if os.path.exists(path):
        os.remove(path)

# ---------------- GUI utils ----------------
def list_scan_files():
    files = []
    for d in SCAN_DIRS:
        if os.path.isdir(d):
            for f in sorted(os.listdir(d)):
                if f.lower().endswith((".nessus", ".nessus.gz")):
                    files.append(os.path.join(d, f))
    return files

def collect_list_from_text(widget: tk.Text):
    raw = widget.get("1.0","end")
    if not raw.strip():
        return []
    parts = re.split(r"[,\s]+", raw.strip())
    return [p for p in (s.strip() for s in parts) if p]

def append_cves_to_cvebox(cve_list):
    existing = set(c.upper() for c in collect_list_from_text(cve_text))
    new = []
    for c in cve_list:
        cu = c.upper()
        if cu not in existing:
            new.append(cu)
            existing.add(cu)
    if new:
        cve_text.insert("end", ("\n" if cve_text.get("1.0","end").strip() else "") + "\n".join(new) + "\n")
    return len(new)

def append_pids_to_pidbox(pid_list):
    existing = set(collect_list_from_text(pid_text))
    new = []
    for p in pid_list:
        ps = str(p)
        if ps not in existing:
            new.append(ps); existing.add(ps)
    if new:
        pid_text.insert("end", ("\n" if pid_text.get("1.0","end").strip() else "") + "\n".join(new) + "\n")
    return len(new)

def show_text_popup(title: str, text: str):
    dlg = tk.Toplevel(root)
    dlg.title(title)
    dlg.geometry("900x520")
    dlg.transient(root); dlg.grab_set()
    txt = tk.Text(dlg, wrap="none")
    sx = ttk.Scrollbar(dlg, orient="horizontal", command=txt.xview)
    sy = ttk.Scrollbar(dlg, orient="vertical", command=txt.yview)
    txt.configure(xscrollcommand=sx.set, yscrollcommand=sy.set)
    txt.grid(row=0, column=0, sticky="nsew")
    sy.grid(row=0, column=1, sticky="ns")
    sx.grid(row=1, column=0, sticky="ew")
    dlg.rowconfigure(0, weight=1)
    dlg.columnconfigure(0, weight=1)
    btn = ttk.Button(dlg, text="Close", command=dlg.destroy)
    btn.grid(row=2, column=0, sticky="e", padx=6, pady=6)
    txt.insert("1.0", text or "(no details)")
    txt.configure(state="disabled")
    apply_text_widget_theme(txt)

def show_hosts_popup(title: str, text: str):
    dlg = tk.Toplevel(root)
    dlg.title(title)
    dlg.geometry("900x520")
    dlg.transient(root); dlg.grab_set()

    txt = tk.Text(dlg, wrap="none")
    sx = ttk.Scrollbar(dlg, orient="horizontal", command=txt.xview)
    sy = ttk.Scrollbar(dlg, orient="vertical", command=txt.yview)
    txt.configure(xscrollcommand=sx.set, yscrollcommand=sy.set)

    txt.grid(row=0, column=0, sticky="nsew")
    sy.grid(row=0, column=1, sticky="ns")
    sx.grid(row=1, column=0, sticky="ew")

    btn_row_local = ttk.Frame(dlg, padding=6)
    btn_row_local.grid(row=2, column=0, columnspan=2, sticky="ew")
    btn_row_local.columnconfigure(0, weight=1)

    def _copy():
        try:
            dlg.clipboard_clear()
            dlg.clipboard_append(txt.get("1.0", "end-1c"))
        except Exception:
            pass

    ttk.Button(btn_row_local, text="Copy to Clipboard", command=_copy).grid(row=0, column=0, sticky="w")
    ttk.Button(btn_row_local, text="Close", command=dlg.destroy).grid(row=0, column=1, sticky="e")

    dlg.rowconfigure(0, weight=1)
    dlg.columnconfigure(0, weight=1)

    txt.insert("1.0", text or "(no hosts)")
    txt.configure(state="disabled")
    apply_text_widget_theme(txt)

def hosts_from_tree(tree: ET.ElementTree):
    root = tree.getroot()
    report = root.find("Report")
    if report is None:
        return []
    out = []
    for host in report.findall("ReportHost"):
        ids = host_ids_from_reporthost(host)
        host_disp = ids[0] if ids else (host.get("name") or "(unnamed)")
        findings = len(host.findall("ReportItem"))
        out.append((host_disp, findings))
    return out

def attach_context_menu(text_widget: tk.Text, mode: str):
    """
    mode ∈ {"cve", "pid", "generic"}
    """
    is_cve = (mode == "cve")
    is_pid = (mode == "pid")

    menu = tk.Menu(text_widget, tearoff=0)

    def _cut(): text_widget.event_generate("<<Cut>>")
    def _copy(): text_widget.event_generate("<<Copy>>")
    def _paste(): text_widget.event_generate("<<Paste>>")
    def _select_all(): text_widget.tag_add("sel", "1.0", "end-1c")
    def _clear(): text_widget.delete("1.0", "end")

    def _dedup_sort_current():
        raw = text_widget.get("1.0","end")
        if is_cve:
            tokens = [m.group(0).upper() for m in CVE_TOKEN_RE.finditer(raw)]
            tokens = sorted(set(tokens))
            text_widget.delete("1.0","end")
            if tokens:
                text_widget.insert("end", "\n".join(tokens) + "\n")
        elif is_pid:
            nums = re.findall(r"\d+", raw)
            nums = sorted(set(int(n) for n in nums))
            text_widget.delete("1.0","end")
            if nums:
                text_widget.insert("end", "\n".join(str(n) for n in nums) + "\n")
        else:
            lines = [ln.strip() for ln in raw.splitlines() if ln.strip()]
            text_widget.delete("1.0","end")
            if lines:
                text_widget.insert("end", "\n".join(lines) + "\n")

    def _normalize_from_clipboard():
        try:
            clip = text_widget.clipboard_get()
        except Exception:
            clip = ""
        if not clip:
            return
        if is_cve:
            tokens = [m.group(0).upper() for m in CVE_TOKEN_RE.finditer(clip)]
            tokens = sorted(set(tokens))
            if tokens:
                if text_widget.get("1.0","end").strip():
                    text_widget.insert("insert", "\n")
                text_widget.insert("insert", "\n".join(tokens) + "\n")
        elif is_pid:
            nums = re.findall(r"\d+", clip)
            nums = sorted(set(int(n) for n in nums))
            if nums:
                if text_widget.get("1.0","end").strip():
                    text_widget.insert("insert", "\n")
                text_widget.insert("insert", "\n".join(str(n) for n in nums) + "\n")
        else:
            tokens = [tok for tok in re.split(r"[,\s]+", clip) if tok.strip()]
            tokens = sorted(set(tokens))
            if tokens:
                if text_widget.get("1.0","end").strip():
                    text_widget.insert("insert", "\n")
                text_widget.insert("insert", "\n".join(tokens) + "\n")

    menu.add_command(label="Cut", command=_cut)
    menu.add_command(label="Copy", command=_copy)
    menu.add_command(label="Paste", command=_paste)
    menu.add_separator()
    menu.add_command(label="Select All", command=_select_all)
    menu.add_command(label="Clear", command=_clear)
    menu.add_separator()
    menu.add_command(label="Deduplicate & Sort", command=_dedup_sort_current)
    menu.add_command(label="Normalize from Clipboard", command=_normalize_from_clipboard)

    def _popup(event):
        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()

    text_widget.bind("<Button-3>", _popup)
    text_widget.bind("<Control-Button-1>", _popup)

# --- Selection dialog (two-pane) ---
def show_expand_selection_dialog(cve_to_context: dict, plugin_list: list, source_label: str):
    dlg = tk.Toplevel(root)
    dlg.title(f"Expand results — {source_label}")
    dlg.transient(root); dlg.grab_set()
    dlg.geometry("1100x700")

    dlg.rowconfigure(0, weight=1)
    dlg.columnconfigure(0, weight=1)

    container = ttk.Frame(dlg, padding=10)
    container.grid(row=0, column=0, sticky="nsew")
    container.columnconfigure(0, weight=1)
    container.columnconfigure(1, weight=1)
    container.rowconfigure(1, weight=1)

    ttk.Label(container, text=f"CVEs ({len(cve_to_context)}):").grid(row=0, column=0, sticky="w")
    ttk.Label(container, text=f"Plugins ({len(plugin_list)}):").grid(row=0, column=1, sticky="w")

    lframe = ttk.Frame(container); lframe.grid(row=1, column=0, sticky="nsew", padx=(0,8))
    lframe.rowconfigure(0, weight=1); lframe.columnconfigure(0, weight=1)
    lbox = tk.Listbox(lframe, selectmode="extended"); lbox.grid(row=0, column=0, sticky="nsew")
    lscroll = ttk.Scrollbar(lframe, orient="vertical", command=lbox.yview); lscroll.grid(row=0, column=1, sticky="ns")
    lbox.configure(yscrollcommand=lscroll.set)

    rows_cve = []
    for cve, ctx in sorted(cve_to_context.items()):
        if cve in SESSION_BLACKLIST_CVES:
            continue
        disp = f"{cve}  —  {(sorted(ctx)[0] if ctx else '')}"
        rows_cve.append((disp, cve))
        lbox.insert("end", disp)

    rframe = ttk.Frame(container); rframe.grid(row=1, column=1, sticky="nsew", padx=(8,0))
    rframe.rowconfigure(0, weight=1); rframe.columnconfigure(0, weight=1)
    rbox = tk.Listbox(rframe, selectmode="extended"); rbox.grid(row=0, column=0, sticky="nsew")
    rscroll = ttk.Scrollbar(rframe, orient="vertical", command=rbox.yview); rscroll.grid(row=0, column=1, sticky="ns")
    rbox.configure(yscrollcommand=rscroll.set)

    rows_pid = []
    for pid, name in sorted(plugin_list):
        if pid in SESSION_BLACKLIST_PIDS:
            continue
        disp = f"{pid}  —  {name}"
        rows_pid.append((disp, pid))
        rbox.insert("end", disp)

    added_cves, dropped_cves, added_pids, dropped_pids = [], [], [], []

    def add_sel(box, rows, out):
        for i in box.curselection():
            out.append(rows[i][1])

    def drop_sel(box, rows, out, is_cve):
        for i in box.curselection():
            val = rows[i][1]
            out.append(val)
            (SESSION_BLACKLIST_CVES if is_cve else SESSION_BLACKLIST_PIDS).add(val)

    def add_all(rows, out):
        for _, val in rows:
            out.append(val)

    def drop_all(rows, out, is_cve):
        for _, val in rows:
            out.append(val)
            (SESSION_BLACKLIST_CVES if is_cve else SESSION_BLACKLIST_PIDS).add(val)

    btns = ttk.Frame(dlg, padding=10); btns.grid(row=1, column=0, sticky="ew")
    btns.columnconfigure(0, weight=1)

    ttk.Button(btns, text="Add CVE(s)", command=lambda: add_sel(lbox, rows_cve, added_cves)).grid(row=0, column=0, sticky="w")
    ttk.Button(btns, text="Drop CVE(s)", command=lambda: drop_sel(lbox, rows_cve, dropped_cves, True)).grid(row=0, column=1, sticky="w", padx=6)
    ttk.Button(btns, text="Add ALL CVEs", command=lambda: add_all(rows_cve, added_cves)).grid(row=0, column=2, sticky="w", padx=(14,6))
    ttk.Button(btns, text="Drop ALL CVEs", command=lambda: drop_all(rows_cve, dropped_cves, True)).grid(row=0, column=3, sticky="w")

    ttk.Button(btns, text="Add Plugin(s)", command=lambda: add_sel(rbox, rows_pid, added_pids)).grid(row=1, column=0, sticky="w", pady=(6,0))
    ttk.Button(btns, text="Drop Plugin(s)", command=lambda: drop_sel(rbox, rows_pid, dropped_pids, False)).grid(row=1, column=1, sticky="w", padx=6, pady=(6,0))
    ttk.Button(btns, text="Add ALL Plugins", command=lambda: add_all(rows_pid, added_pids)).grid(row=1, column=2, sticky="w", padx=(14,6), pady=(6,0))
    ttk.Button(btns, text="Drop ALL Plugins", command=lambda: drop_all(rows_pid, dropped_pids, False)).grid(row=1, column=3, sticky="w", pady=(6,0))

    ttk.Button(btns, text="Done", command=dlg.destroy).grid(row=1, column=4, padx=10, sticky="e")

    apply_listbox_theme(lbox)
    apply_listbox_theme(rbox)

    dlg.wait_window()
    return added_cves, dropped_cves, added_pids, dropped_pids

# --- Themeable helpers for widgets ---
def apply_treeview_theme(tv: ttk.Treeview):
    theme = THEMES.get(current_theme_name.get(), THEMES["VSCode Dark+"])
    style.configure("Treeview",
                    background=theme["box"],
                    fieldbackground=theme["box"],
                    foreground=theme["fg"],
                    bordercolor=theme["border"])
    style.map("Treeview",
              background=[("selected", theme["sel"])],
              foreground=[("selected", theme["fg"])])
    tv.tag_configure("odd", background=theme["box"])
    alt = "#2a2a2a" if current_theme_name.get() != "Light" else "#F6F6F6"
    tv.tag_configure("even", background=alt)

def show_rule_wizard(keyword: str, parent):
    kw = (keyword or "").strip()
    if not kw:
        messagebox.showinfo("CPE Wizard", "Enter a keyword first (e.g., ssh).")
        return

    strict_pat     = rf"(?i)\b{re.escape(kw)}\b"
    balanced_pat   = rf"(?i)(?<![a-z0-9]){re.escape(kw)}(?![a-z0-9])"
    aggressive_pat = rf"(?i){re.escape(kw)}"

    w = tk.Toplevel(parent)
    w.title(f"CPE Rule Wizard — {kw}")
    w.geometry("720x560")
    w.transient(parent); w.grab_set()

    header = ttk.Frame(w, padding=(10,10,10,6))
    header.pack(fill="x")
    ttk.Label(header, text=f"Create Name/CPE Rule for:  {kw}", font=("Segoe UI", 11, "bold")).pack(anchor="w")

    radios = ttk.Frame(w, padding=(10,0,10,6))
    radios.pack(fill="x")
    rule_strength_var = tk.StringVar(value="balanced")
    ttk.Radiobutton(radios, text=f"Ultra-strict — exact token only\n    {strict_pat}", variable=rule_strength_var, value="strict").pack(anchor="w", pady=3)
    ttk.Radiobutton(radios, text=f"Balanced — product-family token (recommended)\n    {balanced_pat}", variable=rule_strength_var, value="balanced").pack(anchor="w", pady=3)
    ttk.Radiobutton(radios, text=f"Aggressive — match anywhere\n    {aggressive_pat}", variable=rule_strength_var, value="aggressive").pack(anchor="w", pady=3)

    ttk.Label(w, text="Preview (matching plugin names):", padding=(10,8,10,0)).pack(anchor="w")

    table_frame = ttk.Frame(w, padding=(10,6,10,6))
    table_frame.pack(fill="both", expand=True)

    cols = ("pid", "name")
    tv = ttk.Treeview(table_frame, columns=cols, show="headings", selectmode="browse")
    tv.heading("pid", text="Plugin ID")
    tv.heading("name", text="Plugin Name")
    tv.column("pid", width=120, anchor="w")
    tv.column("name", anchor="w")
    tv.pack(fill="both", expand=True, side="left")

    vsb = ttk.Scrollbar(table_frame, orient="vertical", command=tv.yview)
    tv.configure(yscrollcommand=vsb.set)
    vsb.pack(fill="y", side="right")

    apply_treeview_theme(tv)

    def _current_pattern() -> str:
        mode = rule_strength_var.get()
        if mode == "strict": return strict_pat
        if mode == "aggressive": return aggressive_pat
        return balanced_pat

    def _preview():
        for r in tv.get_children():
            tv.delete(r)

        pat = _current_pattern()
        try:
            rx = re.compile(pat, re.IGNORECASE)
        except Exception as e:
            messagebox.showerror("CPE Wizard", f"Invalid regex:\n{e}")
            return

        results = []
        if db_available():
            try:
                con = sqlite3.connect(DB_PATH)
                cur = con.cursor()
                cur.execute("SELECT plugin_id, name FROM plugins")
                for pid, nm in cur.fetchall():
                    nm = nm or ""
                    if nm and rx.search(nm):
                        results.append((pid, nm))
            finally:
                try: con.close()
                except: pass

        if not results:
            tv.insert("", "end", values=("", "No plugins would match this rule."), tags=("odd",))
        else:
            for idx, (pid, nm) in enumerate(results):
                tv.insert("", "end", values=(pid, nm), tags=("even" if idx % 2 else "odd",))

    def _apply_rule():
        pat = _current_pattern()
        existing_lines = set(line.strip() for line in namecpe_text.get("1.0","end").splitlines() if line.strip())
        if pat not in existing_lines:
            if namecpe_text.get("1.0","end").strip():
                namecpe_text.insert("end", "\n")
            namecpe_text.insert("end", pat + "\n")
        if pat not in SESSION_NAMECPE_PATTERNS:
            SESSION_NAMECPE_PATTERNS.append(pat)
        w.destroy()

    btnf = ttk.Frame(w, padding=(10,4,10,10))
    btnf.pack(fill="x")
    ttk.Button(btnf, text="Preview", command=_preview).pack(side="left")
    ttk.Button(btnf, text="Apply Rule", command=_apply_rule).pack(side="left", padx=8)
    ttk.Button(btnf, text="Cancel", command=w.destroy).pack(side="right")

# ---------------- GUI ----------------
root = tk.Tk()
root.title("VulnFilter")
root.minsize(1100, 740)

style = ttk.Style()

THEMES = {
    "Light": {
        "base": "vista" if os.name == "nt" else "default",
        "bg": "#F3F3F3", "fg": "#111111", "muted": "#666666",
        "acc": "#0B6EFD", "box": "#FFFFFF", "border": "#C9C9C9", "sel": "#DDEBFF"
    },
    "VSCode Dark+": {
        "base": "clam",
        "bg": "#1E1E1E", "fg": "#D4D4D4", "muted": "#9C9C9C",
        "acc": "#007ACC", "box": "#252526", "border": "#3C3C3C", "sel": "#094771"
    },
    "Nord Dark": {
        "base": "clam",
        "bg": "#2E3440", "fg": "#ECEFF4", "muted": "#C7D0DC",
        "acc": "#88C0D0", "box": "#3B4252", "border": "#434C5E", "sel": "#4C566A"
    },
    "High-Contrast Dark": {
        "base": "clam",
        "bg": "#000000", "fg": "#FFFFFF", "muted": "#E0E0E0",
        "acc": "#FFCC00", "box": "#111111", "border": "#333333", "sel": "#222222"
    }
}

current_theme_name = tk.StringVar(value="VSCode Dark+")

def apply_text_widget_theme(tw: tk.Text):
    theme = THEMES.get(current_theme_name.get(), THEMES["VSCode Dark+"])
    tw.configure(
        background=theme["box"],
        foreground=theme["fg"],
        insertbackground=theme["fg"],
        highlightbackground=theme["border"],
        highlightcolor=theme["acc"],
        selectbackground=theme["sel"],
        selectforeground=theme["fg"]
    )

def apply_listbox_theme(lb: tk.Listbox):
    theme = THEMES.get(current_theme_name.get(), THEMES["VSCode Dark+"])
    lb.configure(
        background=theme["box"],
        foreground=theme["fg"],
        selectbackground=theme["sel"],
        selectforeground=theme["fg"],
        highlightbackground=theme["border"],
        highlightcolor=theme["acc"],
        borderwidth=1
    )

def apply_theme(name: str):
    theme = THEMES.get(name, THEMES["VSCode Dark+"])
    try:
        style.theme_use(theme["base"])
    except:
        style.theme_use("clam")

    bg = theme["bg"]; fg = theme["fg"]; acc = theme["acc"]
    box = theme["box"]; border = theme["border"]; muted = theme["muted"]; sel = theme["sel"]

    root.configure(bg=bg)
    style.configure(".", background=bg, foreground=fg)
    style.configure("TFrame", background=bg)
    style.configure("TLabel", background=bg, foreground=fg)
    style.configure("TButton", background=box, foreground=fg, bordercolor=border, focusthickness=1, focuscolor=acc)
    style.map("TButton",
              background=[("active", box)],
              foreground=[("disabled", muted)],
              relief=[("pressed", "sunken"), ("!pressed", "raised")])
    style.configure("TEntry", fieldbackground=box, foreground=fg, bordercolor=border)
    style.configure("TCombobox", fieldbackground=box, foreground=fg, bordercolor=border, arrowcolor=fg)
    style.map("TCombobox", fieldbackground=[("readonly", box)])
    style.configure("TCheckbutton", background=bg, foreground=fg)
    style.configure("TRadiobutton", background=bg, foreground=fg)
    style.configure("Horizontal.TScrollbar", background=bg, troughcolor=box, bordercolor=border, arrowcolor=fg)
    style.configure("Vertical.TScrollbar",   background=bg, troughcolor=box, bordercolor=border, arrowcolor=fg)
    style.configure("TProgressbar", background=acc, troughcolor=box, bordercolor=border)
    style.configure("Treeview", background=box, fieldbackground=box, foreground=fg, bordercolor=border)

    status_lbl.configure(foreground=muted)
    expand_lbl.configure(foreground=muted)

    for tw in (cve_text, pid_text, ep_text, namecpe_text):
        apply_text_widget_theme(tw)

main = ttk.Frame(root, padding=12)
main.grid(sticky="nsew")
root.columnconfigure(0, weight=1)
root.rowconfigure(0, weight=1)

title_bar = ttk.Frame(main)
title_bar.grid(row=0, column=0, columnspan=10, sticky="ew", pady=(0,8))
title_bar.columnconfigure(0, weight=1)

title_lbl = ttk.Label(title_bar, text="VulnFilter", font=("Segoe UI", 14, "bold"))
title_lbl.grid(row=0, column=0, sticky="w")

theme_menu_btn = ttk.Menubutton(title_bar, text="⋮", width=3)
theme_menu = tk.Menu(theme_menu_btn, tearoff=0)
theme_var = tk.StringVar(value=current_theme_name.get())
def _select_theme(name):
    current_theme_name.set(name)
    apply_theme(name)
for tname in THEMES.keys():
    theme_menu.add_radiobutton(label=tname, variable=theme_var,
                               value=tname, command=lambda n=tname: _select_theme(n))
theme_menu_btn["menu"] = theme_menu
theme_menu_btn.grid(row=0, column=1, sticky="e")

# Scan picker
ttk.Label(main, text="Scan file or folder (recursive):").grid(row=1, column=0, sticky="w")
scan_var = tk.StringVar()
scan_combo = ttk.Combobox(main, textvariable=scan_var, width=85, values=list_scan_files(), state="readonly")
scan_combo.grid(row=2, column=0, columnspan=5, sticky="ew", pady=(0,8))

def on_refresh():
    scan_combo['values'] = list_scan_files()
    if not scan_var.get() and scan_combo['values']:
        scan_var.set(scan_combo['values'][0])

def on_browse_file():
    path = filedialog.askopenfilename(
        title="Select .nessus file",
        filetypes=[("Nessus exports", "*.nessus;*.nessus.gz"), ("All files", "*.*")]
    )
    if path:
        vals = list(scan_combo['values'])
        if path not in vals:
            vals.insert(0, path)
            scan_combo['values'] = vals
        scan_var.set(path)

def on_browse_folder():
    path = filedialog.askdirectory(title="Select a folder containing .nessus files (recursive)")
    if path:
        vals = list(scan_combo['values'])
        if path not in vals:
            vals.insert(0, path)
            scan_combo['values'] = vals
        scan_var.set(path)

ttk.Button(main, text="Refresh list", command=on_refresh).grid(row=2, column=5, sticky="e", padx=(8,0))
ttk.Button(main, text="Browse File…", command=on_browse_file).grid(row=2, column=6, sticky="e", padx=(8,0))
ttk.Button(main, text="Browse Folder…", command=on_browse_folder).grid(row=2, column=7, sticky="e", padx=(8,0))

# Mode toggle (NEW)
mode_frame = ttk.Frame(main)
mode_frame.grid(row=3, column=0, columnspan=10, sticky="w", pady=(2,6))
ttk.Label(mode_frame, text="Mode:").grid(row=0, column=0, padx=(0,8), sticky="w")
mode_var = tk.StringVar(value="drop")
ttk.Radiobutton(mode_frame, text="Drop (remove matches)", value="drop", variable=mode_var).grid(row=0, column=1, padx=(0,12), sticky="w")
ttk.Radiobutton(mode_frame, text="Include-only (keep matches only)", value="include", variable=mode_var).grid(row=0, column=2, padx=(0,12), sticky="w")

# Keyword → Expand (DB ONLY)
ttk.Label(main, text="Keyword / CVE / Plugin ID to expand (DB only):").grid(row=4, column=0, sticky="w")
keyword_var = tk.StringVar()
keyword_entry = ttk.Entry(main, textvariable=keyword_var)
keyword_entry.grid(row=5, column=0, columnspan=2, sticky="ew", padx=(0,4))

expand_status = tk.StringVar(value=("DB ready." if db_available() else "DB not found — Update Database first."))
expand_lbl = ttk.Label(main, textvariable=expand_status)
expand_lbl.grid(row=5, column=2, columnspan=2, sticky="w")

def on_expand_keyword():
    if not db_available():
        messagebox.showerror("Expand", f"Database not found at:\n{DB_PATH}\n\nRun 'Update Database' first.")
        expand_status.set("DB missing.")
        return

    kw = keyword_var.get().strip()
    if not kw:
        messagebox.showinfo("Expand", "Enter a keyword, CVE (e.g., CVE-2022-44702), or plugin ID (e.g., 170016).")
        return

    expand_status.set("Searching DB…")

    def work():
        global LAST_KEYWORD
        try:
            all_cves = set()
            cve_context = {}
            plugin_list = []

            db_cves, db_plugins = db_find_cves_and_plugins(kw)
            for c in db_cves:
                if c not in SESSION_BLACKLIST_CVES:
                    all_cves.add(c)
                    cve_context.setdefault(c, set())

            seen_pids = set()
            for pid, nm in (db_plugins or []):
                pid_i = int(pid)
                if pid_i in seen_pids or pid_i in SESSION_BLACKLIST_PIDS:
                    continue
                plugin_list.append((pid_i, nm or ""))
                seen_pids.add(pid_i)

            if not all_cves and not plugin_list:
                root.after(0, lambda: messagebox.showinfo("Expand", f"No DB matches for: {kw}"))
                expand_status.set("No matches.")
                return

            try:
                title_map = db_guess_cve_titles([c for c in all_cves if not cve_context.get(c)])
                for cve, title in title_map.items():
                    if title:
                        cve_context.setdefault(cve, set()).add(title)
            except Exception:
                pass

            def show_and_get():
                global LAST_KEYWORD
                added_cves, dropped_cves, added_pids, dropped_pids = show_expand_selection_dialog(
                    cve_context, plugin_list, "DB"
                )
                n_cves = append_cves_to_cvebox(added_cves) if added_cves else 0
                n_pids = append_pids_to_pidbox(added_pids) if added_pids else 0
                expand_status.set(f"Added {n_cves} CVEs, {n_pids} plugins; Dropped {len(dropped_cves)} CVEs, {len(dropped_pids)} plugins.")

                if drop_namecpe_from_kw_var.get():
                    show_rule_wizard(kw, root)

                LAST_KEYWORD = kw

            root.after(0, show_and_get)
        finally:
            root.after(0, lambda: keyword_entry.focus())

    threading.Thread(target=work, daemon=True).start()

expand_btn = ttk.Button(main, text="Expand", command=on_expand_keyword)
expand_btn.grid(row=5, column=4, sticky="w", padx=(8,0))
keyword_entry.bind("<Return>", lambda event: on_expand_keyword())

cpe_btn = ttk.Button(main, text="CPE Wizard", command=lambda: show_rule_wizard(keyword_var.get(), root))
cpe_btn.grid(row=5, column=5, sticky="w", padx=(8,0))

drop_namecpe_from_kw_var = tk.BooleanVar(value=False)
ttk.Checkbutton(main, text="After expand, open CPE Rule Wizard", variable=drop_namecpe_from_kw_var)\
    .grid(row=5, column=6, columnspan=3, sticky="w", padx=(12,0))

# Inputs row labels
ttk.Label(main, text="CVEs (comma or one per line):").grid(row=6, column=0, sticky="w", pady=(6,0))
ttk.Label(main, text="Plugin IDs:").grid(row=6, column=1, sticky="w", pady=(6,0))
ttk.Label(main, text="Endpoints (IPs/hostnames/CIDR):").grid(row=6, column=2, columnspan=4, sticky="w", pady=(6,0))
ttk.Label(main, text="Name/CPE rules (regex, one per line):").grid(row=6, column=6, columnspan=3, sticky="w", pady=(6,0))

# Inputs
cve_text = tk.Text(main, height=12, width=48); cve_text.grid(row=7, column=0, columnspan=1, sticky="nsew", padx=(0,8))
pid_text = tk.Text(main, height=12, width=22); pid_text.grid(row=7, column=1, columnspan=1, sticky="nsew", padx=(0,8))
ep_text  = tk.Text(main, height=12, width=40); ep_text.grid(row=7, column=2, columnspan=4, sticky="nsew", padx=(0,8))
namecpe_text = tk.Text(main, height=12, width=32); namecpe_text.grid(row=7, column=6, columnspan=3, sticky="nsew")

attach_context_menu(cve_text, "cve")
attach_context_menu(pid_text, "pid")
attach_context_menu(ep_text, "generic")
attach_context_menu(namecpe_text, "generic")

# Options
opt_frame = ttk.Frame(main); opt_frame.grid(row=8, column=0, columnspan=9, sticky="w", pady=(8,0))
ep_mode_var = tk.StringVar(value="exact")
ttk.Label(opt_frame, text="Endpoint match:").grid(row=0, column=0, padx=(0,8), sticky="w")
for i, (label, val) in enumerate([("exact", "exact"), ("glob", "glob"), ("regex", "regex")], start=1):
    ttk.Radiobutton(opt_frame, text=label, value=val, variable=ep_mode_var).grid(row=0, column=i, padx=(0,12), sticky="w")

prune_var = tk.BooleanVar(value=True)
ttk.Checkbutton(opt_frame, text="Prune hosts that end with 0 findings", variable=prune_var)\
    .grid(row=0, column=4, padx=(8,0), sticky="w")

# Profiles
prof_frame = ttk.Frame(main); prof_frame.grid(row=9, column=0, columnspan=9, sticky="ew", pady=(8,0))
ttk.Label(prof_frame, text="Profile:").grid(row=0, column=0, sticky="w")

profile_var = tk.StringVar()
profile_combo = ttk.Combobox(prof_frame, textvariable=profile_var, width=40, values=list_profiles(), state="readonly")
profile_combo.grid(row=0, column=1, sticky="w", padx=(4,8))

def refresh_profiles():
    profile_combo['values'] = list_profiles()

def on_profile_load():
    global SESSION_NAMECPE_PATTERNS
    name = profile_var.get().strip()
    if not name:
        messagebox.showinfo("Profiles", "Select a profile to load.")
        return
    try:
        data = load_profile(name)
    except Exception as e:
        messagebox.showerror("Profiles", f"Failed to load profile: {e}")
        return
    cve_text.delete("1.0","end")
    pid_text.delete("1.0","end")
    ep_text.delete("1.0","end")
    namecpe_text.delete("1.0","end")
    cve_text.insert("end", "\n".join(data.get("cves", [])) + ("\n" if data.get("cves") else ""))
    pid_text.insert("end", "\n".join(map(str, data.get("plugin_ids", []))) + ("\n" if data.get("plugin_ids") else ""))
    ep_text.insert("end", "\n".join(data.get("endpoints", [])) + ("\n" if data.get("endpoints") else ""))
    name_rules = data.get("namecpe_rules", [])
    if name_rules:
        namecpe_text.insert("end", "\n".join(name_rules) + "\n")
    SESSION_NAMECPE_PATTERNS = list(name_rules)
    ep_mode_var.set(data.get("ep_mode", "exact"))
    prune_var.set(bool(data.get("prune_empty", True)))
    mode_var.set(data.get("mode", "drop"))
    messagebox.showinfo("Profiles", f"Loaded profile '{name}'.")

def on_profile_save():
    def do_save():
        name = simple_name.get().strip()
        if not name:
            messagebox.showerror("Profiles", "Profile name is required.")
            return
        try:
            prof = {
                "cves": [c.upper() for c in collect_list_from_text(cve_text)],
                "plugin_ids": collect_list_from_text(pid_text),
                "endpoints": collect_list_from_text(ep_text),
                "namecpe_rules": [r for r in namecpe_text.get("1.0","end").splitlines() if r.strip()],
                "ep_mode": ep_mode_var.get(),
                "prune_empty": bool(prune_var.get()),
                "mode": mode_var.get(),
            }
            clean_pids = []
            for p in prof["plugin_ids"]:
                try:
                    clean_pids.append(int(p))
                except ValueError:
                    continue
            prof["plugin_ids"] = clean_pids
            save_profile(name, prof)
            refresh_profiles()
            messagebox.showinfo("Profiles", f"Saved profile '{name}'.")
            popup.destroy()
        except Exception as e:
            messagebox.showerror("Profiles", f"Failed to save profile: {e}")

    popup = tk.Toplevel(root)
    popup.title("Save Profile")
    ttk.Label(popup, text="Profile name:").grid(row=0, column=0, padx=8, pady=8, sticky="w")
    default_name = f"profile_{time.strftime('%Y-%m-%d_%H-%M-%S')}"
    simple_name = tk.StringVar(value=default_name)
    ttk.Entry(popup, textvariable=simple_name, width=40).grid(row=0, column=1, padx=8, pady=8, sticky="w")
    ttk.Button(popup, text="Save", command=do_save).grid(row=1, column=0, columnspan=2, pady=(0,8))
    popup.transient(root); popup.grab_set(); popup.focus()

def on_profile_delete():
    name = profile_var.get().strip()
    if not name:
        messagebox.showinfo("Profiles", "Select a profile to delete.")
        return
    if not messagebox.askyesno("Delete Profile", f"Delete profile '{name}'?"):
        return
    try:
        delete_profile(name)
        refresh_profiles()
        profile_var.set("")
        messagebox.showinfo("Profiles", f"Deleted profile '{name}'.")
    except Exception as e:
        messagebox.showerror("Profiles", f"Failed to delete: {e}")

ttk.Button(prof_frame, text="Load",   command=on_profile_load).grid(row=0, column=2, padx=(4,0))
ttk.Button(prof_frame, text="Save",   command=on_profile_save).grid(row=0, column=3, padx=(4,0))
ttk.Button(prof_frame, text="Delete", command=on_profile_delete).grid(row=0, column=4, padx=(4,0))

from typing import Optional

# Buttons
btn_row = ttk.Frame(main)
btn_row.grid(row=10, column=0, columnspan=9, sticky="e", pady=(12, 0))

# Status bar (bottom-left)
status_var = tk.StringVar(value="Idle")
status_lbl = ttk.Label(main, textvariable=status_var)
status_lbl.grid(row=11, column=0, columnspan=9, sticky="w", pady=(8, 0))


def set_ui_busy(busy: bool, msg: Optional[str] = None):
    """
    Controls UI busy state.
    - busy=True  → disables buttons, shows wait cursor
    - busy=False → re-enables buttons
    - msg=None   → do NOT overwrite existing status text
    """
    for child in btn_row.winfo_children():
        child.configure(state=("disabled" if busy else "normal"))

    root.configure(cursor=("wait" if busy else ""))

    if msg is not None:
        status_var.set(msg)

    root.update_idletasks()

def open_output_folder():
    path = OUTPUT_DIR
    try:
        if os.name == "nt":
            os.startfile(path)  # type: ignore[attr-defined]
        elif sys.platform == "darwin":
            subprocess.run(["open", path], check=False)
        else:
            subprocess.run(["xdg-open", path], check=False)
    except Exception:
        messagebox.showinfo("Output", f"Output dir: {path}")

def write_last_run_log():
    global LAST_LOG_PATH
    if not LAST_RUN_DETAILS:
        return None
    ts = time.strftime("%Y%m%d_%H%M%S")
    log_path = os.path.join(LOG_DIR, f"vulnfilter_run_{ts}.log")
    try:
        with open(log_path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(LAST_RUN_DETAILS).rstrip() + "\n")
        LAST_LOG_PATH = log_path
        return log_path
    except Exception:
        return None

def on_view_last_run():
    text = "\n".join(LAST_RUN_DETAILS).strip()
    if not text:
        text = "(No details yet. Run a Dry Run or Export first.)"
    show_text_popup("Last Run Details", text)

def on_view_last_hosts():
    text = (LAST_HOST_LIST_TEXT or "").strip()
    if not text:
        messagebox.showinfo("Hosts", "No host list yet. Run Export Filtered first.")
        return
    show_hosts_popup("Last Host List", text)

def run_filter(dry_run):
    selection = scan_var.get().strip()
    cves_in = [c.upper() for c in collect_list_from_text(cve_text)]
    pid_raw = collect_list_from_text(pid_text)
    endpoints_raw = collect_list_from_text(ep_text)
    namecpe_rules_raw = [r for r in namecpe_text.get("1.0","end").splitlines() if r.strip()]
    for pat in SESSION_NAMECPE_PATTERNS:
        if pat not in namecpe_rules_raw:
            namecpe_rules_raw.append(pat)

    ep_mode = ep_mode_var.get()
    prune_empty = bool(prune_var.get())
    mode = mode_var.get().strip().lower()

    if mode == "include":
        has_include = bool(cves_in) or bool(pid_raw) or bool(namecpe_rules_raw)
        if not has_include:
            messagebox.showerror(
                "Include-only mode",
                "Include-only mode requires at least one selector:\n"
                "- CVEs OR Plugin IDs OR Name/CPE rules.\n\n"
                "Add at least one, or switch back to Drop mode."
            )
            return

    def worker():
        global LAST_HOST_LIST_TEXT
        try:
            LAST_RUN_DETAILS.clear()
            LAST_HOST_LIST_TEXT = ""

            targets = resolve_targets(selection)
            if not targets:
                raise RuntimeError("Pick a .nessus file or a folder containing .nessus files.")

            try:
                pids_set = set(int(x) for x in pid_raw) if pid_raw else set()
            except ValueError:
                raise RuntimeError("Plugin IDs must be integers.")

            try:
                endpoints_prepared = prepare_endpoint_patterns(endpoints_raw, ep_mode)
            except ValueError as ve:
                raise RuntimeError(str(ve))

            try:
                namecpe_compiled = prepare_namecpe_patterns(namecpe_rules_raw)
            except ValueError as ve:
                raise RuntimeError(str(ve))

            total_hosts_removed = 0
            total_items_removed = 0
            processed = 0

            host_lines_by_file = []

            for infile in targets:
                summary, tree, counts = filter_nessus(
                    infile,
                    set(cves_in),
                    pids_set,
                    endpoints_prepared,
                    ep_mode,
                    prune_empty,
                    namecpe_compiled,
                    dry_run=dry_run,
                    mode=mode,
                )

                if not dry_run:
                    try:
                        if mode == "drop":
                            strip_pluginset_ids(tree.getroot(), pids_set)
                        else:
                            keep_only_pluginset_ids(tree.getroot(), pids_set)
                    except Exception:
                        pass

                    outfile = make_output_path(infile)
                    tmpfile = outfile + ".tmp"
                    try:
                        write_nessus_tree(tree, tmpfile)
                        os.replace(tmpfile, outfile)
                    finally:
                        if os.path.exists(tmpfile):
                            try:
                                os.remove(tmpfile)
                            except Exception:
                                pass

                    rows = hosts_from_tree(tree)
                    rows.sort(key=lambda x: x[0].lower())

                    host_lines_by_file.append(f"=== {os.path.basename(infile)} ===")
                    for host_disp, findings in rows:
                        host_lines_by_file.append(f"{host_disp}\t(findings: {findings})")
                    host_lines_by_file.append("")

                total_hosts_removed += counts["hosts_removed"]
                total_items_removed += counts["items_removed"]
                processed += 1

            log_path = write_last_run_log()

            msg = (
                "=== VulnFilter batch summary ===\n"
                f"Mode: {mode}\n"
                f"Targets processed: {processed}\n"
                f"Removed hosts: {total_hosts_removed}\n"
                f"Removed findings: {total_items_removed}\n"
                f"Output folder: {OUTPUT_DIR}\n"
                f"Log: {log_path if log_path else '(failed to write)'}"
            )
            root.after(0, lambda m=msg: messagebox.showinfo("Done", m))

            if not dry_run:
                LAST_HOST_LIST_TEXT = "\n".join(host_lines_by_file).strip()
                root.after(0, lambda: show_hosts_popup("Hosts in Exported Files", LAST_HOST_LIST_TEXT))

        except Exception as ex:
            err_msg = str(ex)
            root.after(0, lambda m=err_msg: messagebox.showerror("Error", m))
        finally:
            root.after(0, progress_popup.destroy)
            root.after(0, lambda: set_ui_busy(False, "Ready."))

    progress_popup = tk.Toplevel(root)
    progress_popup.title("Processing Nessus Files…")
    progress_popup.geometry("420x120")
    progress_popup.transient(root)
    progress_popup.grab_set()

    label_text = "Performing Dry Run…" if dry_run else "Exporting Filtered Files…"
    ttk.Label(progress_popup, text=label_text).pack(pady=8)

    pbar = ttk.Progressbar(progress_popup, mode="indeterminate", length=300)
    pbar.pack(pady=10)
    pbar.start(15)

    apply_theme(current_theme_name.get())

    set_ui_busy(True, "Working…")
    threading.Thread(target=worker, daemon=True).start()

# --- Update Database integration ---
def update_database():
    builder_path = os.path.join(BASE_DIR, "db_builder.py")
    if not os.path.exists(builder_path):
        messagebox.showerror(
            "Database",
            "db_builder.py was not found in this folder.\n\n"
            "Make sure db_builder.py is located next to vulnfilter.py."
        )
        return

    folder = filedialog.askdirectory(title="Select Folder Containing .nessus or .nessus.gz Files")
    if not folder:
        return

    confirm = messagebox.askyesno(
        "Update Database",
        f"Rebuild {DB_PATH} from all Nessus exports under:\n\n{folder}\n\n"
        f"This may take a while. Continue?"
    )
    if not confirm:
        return

    progress_popup = tk.Toplevel(root)
    progress_popup.title("Updating Database…")
    progress_popup.geometry("420x120")
    progress_popup.transient(root)
    progress_popup.grab_set()

    ttk.Label(progress_popup, text="Building Nessus Index (may take several minutes)…").pack(pady=8)

    pbar = ttk.Progressbar(progress_popup, mode="indeterminate", length=300)
    pbar.pack(pady=10)
    pbar.start(15)

    apply_theme(current_theme_name.get())
    set_ui_busy(True, "Updating database…")

    def worker():
        try:
            cmd = [
                sys.executable,
                builder_path,
                "--db", DB_PATH,
                "--in", folder
            ]
            subprocess.run(cmd, check=True)
            root.after(0, lambda: expand_status.set("DB ready."))
            root.after(0, lambda: messagebox.showinfo("Database", "Database updated successfully."))
        except subprocess.CalledProcessError as e:
            root.after(0, lambda: messagebox.showerror("Database", f"Database update failed.\n\n{e}"))
            root.after(0, lambda: expand_status.set("Database update failed."))
        finally:
            root.after(0, lambda: set_ui_busy(False, "Ready."))
            root.after(0, progress_popup.destroy)

    threading.Thread(target=worker, daemon=True).start()

ttk.Button(btn_row, text="Dry Run", command=lambda: run_filter(True)).grid(row=0, column=0, padx=(0,8))
ttk.Button(btn_row, text="Export Filtered", command=lambda: run_filter(False)).grid(row=0, column=1)
ttk.Button(btn_row, text="Open Output Folder", command=open_output_folder).grid(row=0, column=2, padx=(8,0))
ttk.Button(btn_row, text="View Last Run Details", command=on_view_last_run).grid(row=0, column=3, padx=(8,0))
ttk.Button(btn_row, text="View Last Hosts", command=on_view_last_hosts).grid(row=0, column=4, padx=(8,0))
ttk.Button(btn_row, text="Update Database", command=update_database).grid(row=0, column=5, padx=(8,0))
ttk.Button(btn_row, text="Close", command=root.destroy).grid(row=0, column=6, padx=(8,0))

on_refresh()

for c in range(10):
    main.columnconfigure(c, weight=1)
main.rowconfigure(7, weight=1)

apply_theme(current_theme_name.get())

root.mainloop()
