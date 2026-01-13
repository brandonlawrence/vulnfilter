# VulnFilter

VulnFilter is a local, offline GUI tool for surgically filtering vulnerability scan exports for reporting and analysis.

It supports include-only and drop-based filtering by CVE, plugin ID, product name, CPE patterns, and endpoints, while preserving the original scan files.

All processing is performed locally with no cloud connectivity, no APIs, and no data upload.

> **Note:** This project is not affiliated with Tenable or Nessus.

---

## Features

- GUI-based workflow (no CLI required for normal use)
- Include-only and drop-based filtering modes
- Filter by:
  - CVE
  - Plugin ID
  - Product name / family
  - CPE patterns
  - Hostnames, IPs, or CIDR ranges
- Preserves original scan files
- Local SQLite index for fast searching and expansion

---

## Included Tools

### `vulnfilter.py`
Interactive GUI used to filter vulnerability scan exports.

- Uses Python standard library only
- Does not modify original scan files
- Executes all filtering locally

### `db_builder.py`
Utility used to rebuild the local SQLite index from scan exports.

- Parses `.nessus` and `.nessus.gz` files
- Inserts one finding per (source, host, plugin)
- Supports fast search and expand features in the GUI

---

## Requirements

- Python 3.9+
- lxml (required for XML parsing in `db_builder.py`)

---

## License

MIT License
