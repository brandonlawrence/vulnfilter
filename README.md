# VulnFilter

VulnFilter is a local, offline GUI tool for surgically filtering vulnerability scan exports for reporting and analysis.

It supports include-only and drop-based filtering by CVE, plugin ID, product name, CPE patterns, and endpoints, while preserving the original scan files.

All processing is performed locally with no cloud connectivity, no APIs, and no data upload.

---

## Features

- GUI-based workflow (no CLI required for normal use)
- Include-only or drop-based filtering modes
- Filter by:
  - CVE
  - Plugin ID
  - Product name / family
  - CPE patterns
  - Hostnames, IPs, or CIDR ranges
- Preserves original scan files
- Local SQLite index for fast searching and expansion
- No external dependencies (Python standard library only)

---

## Included Tools

- **vulnfilter.py**  
  Interactive GUI used to filter vulnerability scan exports.

- **db_builder.py**  
  Utility to rebuild the local SQLite index from scan exports.  
  Used by the GUI for search and expand functionality.

---

## Usage

1. Run `vulnfilter.py`
2. Use **Update Database** to index your scan exports (one-time or as needed)
3. Select a scan file or folder
4. Configure filters and mode
5. Export filtered results

---

## Security & Privacy

- Runs entirely offline
- No network access
- No telemetry
- No data leaves the system

---

## License

MIT License
