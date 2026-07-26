# cybersecurity-incident-tracker

A simple command-line tool for logging and tracking security incidents and their indicators of compromise (IOCs). No setup, no external dependencies — just Python and SQLite.

Core capabilities:

Incident lifecycle tracking (Open → Investigating → Contained → Eradicated → Recovered → Closed)
Severity and category classification (Phishing, Malware, Ransomware, Data Breach, DDoS, and more)
IOC logging (IPs, domains, URLs, file hashes, emails) linked to each incident
Timestamped investigation timeline/notes per incident
Keyword search across incidents and IOC values
Dashboard with summary statistics by status/severity/category
CSV/JSON export for reporting or import into other tools

Skills & tools used:

Python 3 — core language, standard library only (no external dependencies)
SQLite3 (sqlite3 module) — relational data storage with foreign keys and indexing
argparse — subcommand-based CLI design
CSV/JSON modules — data export
ANSI terminal formatting — color-coded severity/status output for readability
Software design: separation of data layer, CLI layer, and interactive UI layer for maintainability
Git & GitHub — version control and project hosting
