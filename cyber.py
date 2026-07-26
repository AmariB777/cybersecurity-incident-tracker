"""
Cybersecurity Incident Tracker

A lightweight, dependency-free (stdlib only) tool for tracking security
incidents and their indicators of compromise (IOCs).

Features:
  - Create / update / close incidents with severity, category, status
  - Attach IOCs (IPs, domains, URLs, file hashes, emails) to incidents
  - Add timestamped investigation notes (timeline) to incidents
  - Search incidents by keyword or by IOC value
  - Dashboard with summary statistics
  - Export incidents to CSV or JSON
  - Works as a CLI (scriptable) or an interactive menu (just run with no args)

Storage: SQLite database file (default: incidents.db) in the working directory.
"""

import argparse
import csv
import json
import os
import sqlite3
import sys
from datetime import datetime, timezone

DB_FILE = os.environ.get("INCIDENT_DB", "incidents.db")

SEVERITIES = ["Critical", "High", "Medium", "Low", "Informational"]
STATUSES = ["Open", "Investigating", "Contained", "Eradicated", "Recovered", "Closed"]
CATEGORIES = [
    "Malware", "Phishing", "Data Breach", "DDoS", "Insider Threat",
    "Unauthorized Access", "Ransomware", "Misconfiguration", "Other",
]
IOC_TYPES = ["IP", "Domain", "URL", "FileHash", "Email", "Other"]

# ---------- ANSI colors (safe no-ops if terminal doesn't support them) ----------
class C:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[31m"
    ORANGE = "\033[38;5;208m"
    YELLOW = "\033[33m"
    GREEN = "\033[32m"
    BLUE = "\033[34m"
    CYAN = "\033[36m"
    GREY = "\033[90m"

SEVERITY_COLOR = {
    "Critical": C.RED,
    "High": C.ORANGE,
    "Medium": C.YELLOW,
    "Low": C.GREEN,
    "Informational": C.GREY,
}

STATUS_COLOR = {
    "Open": C.RED,
    "Investigating": C.YELLOW,
    "Contained": C.CYAN,
    "Eradicated": C.BLUE,
    "Recovered": C.GREEN,
    "Closed": C.GREY,
}


def colorize(text, color):
    if os.environ.get("NO_COLOR"):
        return text
    return f"{color}{text}{C.RESET}"


def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# ---------------------------- Database layer ----------------------------

def get_conn():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    conn = get_conn()
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT,
            severity TEXT NOT NULL,
            category TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'Open',
            assigned_to TEXT,
            affected_systems TEXT,
            source TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS iocs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id INTEGER NOT NULL,
            ioc_type TEXT NOT NULL,
            value TEXT NOT NULL,
            description TEXT,
            added_at TEXT NOT NULL,
            FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id INTEGER NOT NULL,
            note TEXT NOT NULL,
            author TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_ioc_value ON iocs(value);
        CREATE INDEX IF NOT EXISTS idx_incident_status ON incidents(status);
        CREATE INDEX IF NOT EXISTS idx_incident_severity ON incidents(severity);
        """
    )
    conn.commit()
    conn.close()


# ---------------------------- Validation helpers ----------------------------

def norm_choice(value, choices, field_name):
    if value is None:
        return None
    for c in choices:
        if c.lower() == value.lower():
            return c
    raise ValueError(f"Invalid {field_name} '{value}'. Must be one of: {', '.join(choices)}")


# ---------------------------- Core operations ----------------------------

def add_incident(title, description, severity, category, assigned_to=None,
                  affected_systems=None, source=None, status="Open"):
    severity = norm_choice(severity, SEVERITIES, "severity")
    category = norm_choice(category, CATEGORIES, "category")
    status = norm_choice(status, STATUSES, "status")
    ts = now_iso()
    conn = get_conn()
    cur = conn.execute(
        """INSERT INTO incidents
           (title, description, severity, category, status, assigned_to,
            affected_systems, source, created_at, updated_at)
           VALUES (?,?,?,?,?,?,?,?,?,?)""",
        (title, description, severity, category, status, assigned_to,
         affected_systems, source, ts, ts),
    )
    conn.commit()
    incident_id = cur.lastrowid
    conn.close()
    return incident_id


def update_status(incident_id, status):
    status = norm_choice(status, STATUSES, "status")
    conn = get_conn()
    cur = conn.execute("SELECT id FROM incidents WHERE id=?", (incident_id,))
    if not cur.fetchone():
        conn.close()
        raise ValueError(f"No incident with id {incident_id}")
    conn.execute(
        "UPDATE incidents SET status=?, updated_at=? WHERE id=?",
        (status, now_iso(), incident_id),
    )
    conn.commit()
    conn.close()


def add_ioc(incident_id, ioc_type, value, description=None):
    ioc_type = norm_choice(ioc_type, IOC_TYPES, "ioc_type")
    conn = get_conn()
    cur = conn.execute("SELECT id FROM incidents WHERE id=?", (incident_id,))
    if not cur.fetchone():
        conn.close()
        raise ValueError(f"No incident with id {incident_id}")
    conn.execute(
        """INSERT INTO iocs (incident_id, ioc_type, value, description, added_at)
           VALUES (?,?,?,?,?)""",
        (incident_id, ioc_type, value, description, now_iso()),
    )
    conn.execute("UPDATE incidents SET updated_at=? WHERE id=?", (now_iso(), incident_id))
    conn.commit()
    conn.close()


def add_note(incident_id, note, author=None):
    conn = get_conn()
    cur = conn.execute("SELECT id FROM incidents WHERE id=?", (incident_id,))
    if not cur.fetchone():
        conn.close()
        raise ValueError(f"No incident with id {incident_id}")
    conn.execute(
        "INSERT INTO notes (incident_id, note, author, created_at) VALUES (?,?,?,?)",
        (incident_id, note, author, now_iso()),
    )
    conn.execute("UPDATE incidents SET updated_at=? WHERE id=?", (now_iso(), incident_id))
    conn.commit()
    conn.close()


def delete_incident(incident_id):
    conn = get_conn()
    cur = conn.execute("SELECT id FROM incidents WHERE id=?", (incident_id,))
    if not cur.fetchone():
        conn.close()
        raise ValueError(f"No incident with id {incident_id}")
    conn.execute("DELETE FROM iocs WHERE incident_id=?", (incident_id,))
    conn.execute("DELETE FROM notes WHERE incident_id=?", (incident_id,))
    conn.execute("DELETE FROM incidents WHERE id=?", (incident_id,))
    conn.commit()
    conn.close()


def list_incidents(status_filter=None, severity_filter=None, category_filter=None):
    query = "SELECT * FROM incidents WHERE 1=1"
    params = []
    if status_filter:
        placeholders = ",".join("?" * len(status_filter))
        query += f" AND status IN ({placeholders})"
        params.extend(status_filter)
    if severity_filter:
        placeholders = ",".join("?" * len(severity_filter))
        query += f" AND severity IN ({placeholders})"
        params.extend(severity_filter)
    if category_filter:
        placeholders = ",".join("?" * len(category_filter))
        query += f" AND category IN ({placeholders})"
        params.extend(category_filter)
    query += " ORDER BY CASE severity WHEN 'Critical' THEN 0 WHEN 'High' THEN 1 " \
             "WHEN 'Medium' THEN 2 WHEN 'Low' THEN 3 ELSE 4 END, created_at DESC"
    conn = get_conn()
    rows = conn.execute(query, params).fetchall()
    conn.close()
    return rows


def get_incident(incident_id):
    conn = get_conn()
    incident = conn.execute("SELECT * FROM incidents WHERE id=?", (incident_id,)).fetchone()
    if not incident:
        conn.close()
        return None, [], []
    iocs = conn.execute(
        "SELECT * FROM iocs WHERE incident_id=? ORDER BY added_at", (incident_id,)
    ).fetchall()
    notes = conn.execute(
        "SELECT * FROM notes WHERE incident_id=? ORDER BY created_at", (incident_id,)
    ).fetchall()
    conn.close()
    return incident, iocs, notes


def search(term):
    like = f"%{term}%"
    conn = get_conn()
    incidents = conn.execute(
        """SELECT * FROM incidents WHERE title LIKE ? OR description LIKE ?
           OR affected_systems LIKE ? ORDER BY created_at DESC""",
        (like, like, like),
    ).fetchall()
    ioc_matches = conn.execute(
        """SELECT iocs.*, incidents.title as incident_title FROM iocs
           JOIN incidents ON incidents.id = iocs.incident_id
           WHERE iocs.value LIKE ? OR iocs.description LIKE ?""",
        (like, like),
    ).fetchall()
    conn.close()
    return incidents, ioc_matches


def stats():
    conn = get_conn()
    total = conn.execute("SELECT COUNT(*) c FROM incidents").fetchone()["c"]
    by_status = conn.execute(
        "SELECT status, COUNT(*) c FROM incidents GROUP BY status"
    ).fetchall()
    by_severity = conn.execute(
        "SELECT severity, COUNT(*) c FROM incidents GROUP BY severity"
    ).fetchall()
    by_category = conn.execute(
        "SELECT category, COUNT(*) c FROM incidents GROUP BY category"
    ).fetchall()
    open_critical = conn.execute(
        "SELECT COUNT(*) c FROM incidents WHERE status NOT IN ('Closed','Recovered') "
        "AND severity IN ('Critical','High')"
    ).fetchone()["c"]
    total_iocs = conn.execute("SELECT COUNT(*) c FROM iocs").fetchone()["c"]
    conn.close()
    return {
        "total": total,
        "by_status": {r["status"]: r["c"] for r in by_status},
        "by_severity": {r["severity"]: r["c"] for r in by_severity},
        "by_category": {r["category"]: r["c"] for r in by_category},
        "open_high_critical": open_critical,
        "total_iocs": total_iocs,
    }


def export_data(fmt, out_path):
    conn = get_conn()
    incidents = conn.execute("SELECT * FROM incidents").fetchall()
    conn.close()
    incidents = [dict(r) for r in incidents]

    if fmt == "json":
        with open(out_path, "w") as f:
            json.dump(incidents, f, indent=2)
    elif fmt == "csv":
        if not incidents:
            fieldnames = ["id", "title", "description", "severity", "category",
                          "status", "assigned_to", "affected_systems", "source",
                          "created_at", "updated_at"]
        else:
            fieldnames = list(incidents[0].keys())
        with open(out_path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(incidents)
    else:
        raise ValueError("format must be 'json' or 'csv'")
    return out_path


# ---------------------------- Rendering / display ----------------------------

def render_incident_row(row):
    sev = colorize(f"{row['severity']:<13}", SEVERITY_COLOR.get(row["severity"], ""))
    stat = colorize(f"{row['status']:<13}", STATUS_COLOR.get(row["status"], ""))
    return f"#{row['id']:<4} {sev} {stat} {row['category']:<20} {row['title']}"


def print_incident_table(rows):
    if not rows:
        print(colorize("No incidents found.", C.DIM))
        return
    header = f"{'ID':<5} {'SEVERITY':<13} {'STATUS':<13} {'CATEGORY':<20} TITLE"
    print(colorize(header, C.BOLD))
    print(colorize("-" * len(header), C.GREY))
    for row in rows:
        print(render_incident_row(row))


def print_incident_detail(incident, iocs, notes):
    if not incident:
        print(colorize("Incident not found.", C.RED))
        return
    sev = colorize(incident["severity"], SEVERITY_COLOR.get(incident["severity"], ""))
    stat = colorize(incident["status"], STATUS_COLOR.get(incident["status"], ""))
    print(colorize(f"\n=== Incident #{incident['id']}: {incident['title']} ===", C.BOLD))
    print(f"Severity   : {sev}")
    print(f"Status     : {stat}")
    print(f"Category   : {incident['category']}")
    print(f"Assigned   : {incident['assigned_to'] or '-'}")
    print(f"Systems    : {incident['affected_systems'] or '-'}")
    print(f"Source     : {incident['source'] or '-'}")
    print(f"Created    : {incident['created_at']}")
    print(f"Updated    : {incident['updated_at']}")
    if incident["description"]:
        print(f"\nDescription:\n  {incident['description']}")

    print(colorize(f"\n-- IOCs ({len(iocs)}) --", C.CYAN))
    if iocs:
        for ioc in iocs:
            print(f"  [{ioc['ioc_type']}] {ioc['value']}"
                  f"{'  - ' + ioc['description'] if ioc['description'] else ''}")
    else:
        print(colorize("  none recorded", C.DIM))

    print(colorize(f"\n-- Timeline / Notes ({len(notes)}) --", C.CYAN))
    if notes:
        for n in notes:
            author = f" ({n['author']})" if n["author"] else ""
            print(f"  [{n['created_at']}]{author} {n['note']}")
    else:
        print(colorize("  none recorded", C.DIM))
    print()


def print_stats(s):
    print(colorize("\n=== Incident Dashboard ===", C.BOLD))
    print(f"Total incidents        : {s['total']}")
    print(colorize(f"Open High/Critical      : {s['open_high_critical']}",
                    C.RED if s["open_high_critical"] else C.GREEN))
    print(f"Total IOCs tracked      : {s['total_iocs']}")

    print(colorize("\nBy status:", C.BOLD))
    for status in STATUSES:
        count = s["by_status"].get(status, 0)
        bar = "#" * count
        print(f"  {status:<15} {colorize(bar, STATUS_COLOR.get(status, ''))} {count}")

    print(colorize("\nBy severity:", C.BOLD))
    for sev in SEVERITIES:
        count = s["by_severity"].get(sev, 0)
        bar = "#" * count
        print(f"  {sev:<15} {colorize(bar, SEVERITY_COLOR.get(sev, ''))} {count}")

    print(colorize("\nBy category:", C.BOLD))
    for cat, count in sorted(s["by_category"].items(), key=lambda x: -x[1]):
        bar = "#" * count
        print(f"  {cat:<20} {bar} {count}")
    print()


# ---------------------------- CLI ----------------------------

def parse_list_arg(value):
    if not value:
        return None
    return [v.strip() for v in value.split(",") if v.strip()]


def build_parser():
    p = argparse.ArgumentParser(
        prog="incident_tracker.py",
        description="Cybersecurity Incident Tracker / IOC Indicator tool",
    )
    sub = p.add_subparsers(dest="command")

    a = sub.add_parser("add-incident", help="Create a new incident")
    a.add_argument("-t", "--title", required=True)
    a.add_argument("-d", "--description", default="")
    a.add_argument("-s", "--severity", required=True, choices=SEVERITIES)
    a.add_argument("-c", "--category", required=True, choices=CATEGORIES)
    a.add_argument("--status", default="Open", choices=STATUSES)
    a.add_argument("--assigned", default=None, dest="assigned_to")
    a.add_argument("--systems", default=None, dest="affected_systems")
    a.add_argument("--source", default=None)

    u = sub.add_parser("update-status", help="Update an incident's status")
    u.add_argument("-i", "--id", required=True, type=int, dest="incident_id")
    u.add_argument("--status", required=True, choices=STATUSES)

    io = sub.add_parser("add-ioc", help="Attach an IOC to an incident")
    io.add_argument("-i", "--id", required=True, type=int, dest="incident_id")
    io.add_argument("--type", required=True, choices=IOC_TYPES, dest="ioc_type")
    io.add_argument("--value", required=True)
    io.add_argument("--desc", default=None, dest="description")

    n = sub.add_parser("add-note", help="Add a timeline note to an incident")
    n.add_argument("-i", "--id", required=True, type=int, dest="incident_id")
    n.add_argument("--note", required=True)
    n.add_argument("--author", default=None)

    d = sub.add_parser("delete", help="Delete an incident")
    d.add_argument("-i", "--id", required=True, type=int, dest="incident_id")

    ls = sub.add_parser("list", help="List incidents (with optional filters)")
    ls.add_argument("--status", default=None, help="comma-separated list")
    ls.add_argument("--severity", default=None, help="comma-separated list")
    ls.add_argument("--category", default=None, help="comma-separated list")

    sh = sub.add_parser("show", help="Show full detail for one incident")
    sh.add_argument("-i", "--id", required=True, type=int, dest="incident_id")

    se = sub.add_parser("search", help="Search incidents and IOCs by keyword")
    se.add_argument("term")

    sub.add_parser("stats", help="Show dashboard summary statistics")

    ex = sub.add_parser("export", help="Export incidents to CSV or JSON")
    ex.add_argument("--format", choices=["csv", "json"], default="json")
    ex.add_argument("--out", default=None)

    return p


def run_cli(argv):
    parser = build_parser()
    args = parser.parse_args(argv)
    init_db()

    if args.command is None:
        interactive_menu()
        return

    try:
        if args.command == "add-incident":
            incident_id = add_incident(
                args.title, args.description, args.severity, args.category,
                assigned_to=args.assigned_to, affected_systems=args.affected_systems,
                source=args.source, status=args.status,
            )
            print(colorize(f"Created incident #{incident_id}: {args.title}", C.GREEN))

        elif args.command == "update-status":
            update_status(args.incident_id, args.status)
            print(colorize(f"Incident #{args.incident_id} status -> {args.status}", C.GREEN))

        elif args.command == "add-ioc":
            add_ioc(args.incident_id, args.ioc_type, args.value, args.description)
            print(colorize(f"Added IOC [{args.ioc_type}] {args.value} to incident "
                            f"#{args.incident_id}", C.GREEN))

        elif args.command == "add-note":
            add_note(args.incident_id, args.note, args.author)
            print(colorize(f"Added note to incident #{args.incident_id}", C.GREEN))

        elif args.command == "delete":
            delete_incident(args.incident_id)
            print(colorize(f"Deleted incident #{args.incident_id}", C.YELLOW))

        elif args.command == "list":
            rows = list_incidents(
                parse_list_arg(args.status),
                parse_list_arg(args.severity),
                parse_list_arg(args.category),
            )
            print_incident_table(rows)

        elif args.command == "show":
            incident, iocs, notes = get_incident(args.incident_id)
            print_incident_detail(incident, iocs, notes)

        elif args.command == "search":
            incidents, ioc_matches = search(args.term)
            print(colorize(f"\nIncidents matching '{args.term}':", C.BOLD))
            print_incident_table(incidents)
            print(colorize(f"\nIOCs matching '{args.term}':", C.BOLD))
            if ioc_matches:
                for ioc in ioc_matches:
                    print(f"  [{ioc['ioc_type']}] {ioc['value']} "
                          f"-> incident #{ioc['incident_id']} ({ioc['incident_title']})")
            else:
                print(colorize("  none", C.DIM))

        elif args.command == "stats":
            print_stats(stats())

        elif args.command == "export":
            out = args.out or f"incidents_export.{args.format}"
            path = export_data(args.format, out)
            print(colorize(f"Exported to {path}", C.GREEN))

    except ValueError as e:
        print(colorize(f"Error: {e}", C.RED))
        sys.exit(1)


# ---------------------------- Interactive menu ----------------------------

def prompt(msg, default=None, required=False):
    suffix = f" [{default}]" if default else ""
    while True:
        val = input(f"{msg}{suffix}: ").strip()
        if not val and default is not None:
            return default
        if not val and required:
            print("  This field is required.")
            continue
        return val


def prompt_choice(msg, choices, default=None):
    print(f"{msg} ({', '.join(choices)})")
    return prompt("  choice", default=default, required=default is None)


def interactive_menu():
    print(colorize("\n== Cybersecurity Incident Tracker ==", C.BOLD))
    print(f"Database: {DB_FILE}\n")
    menu = """
 1) Add incident
 2) List incidents
 3) Show incident detail
 4) Update incident status
 5) Add IOC to incident
 6) Add note to incident
 7) Search
 8) Dashboard / stats
 9) Export data
 0) Exit
"""
    while True:
        print(menu)
        choice = input("Select an option: ").strip()
        try:
            if choice == "1":
                title = prompt("Title", required=True)
                description = prompt("Description", default="")
                severity = prompt_choice("Severity", SEVERITIES)
                category = prompt_choice("Category", CATEGORIES)
                assigned_to = prompt("Assigned to", default="")
                systems = prompt("Affected systems (comma-sep)", default="")
                source = prompt("Source", default="")
                iid = add_incident(title, description, severity, category,
                                    assigned_to=assigned_to or None,
                                    affected_systems=systems or None,
                                    source=source or None)
                print(colorize(f"Created incident #{iid}", C.GREEN))

            elif choice == "2":
                rows = list_incidents()
                print_incident_table(rows)

            elif choice == "3":
                iid = int(prompt("Incident ID", required=True))
                incident, iocs, notes = get_incident(iid)
                print_incident_detail(incident, iocs, notes)

            elif choice == "4":
                iid = int(prompt("Incident ID", required=True))
                status = prompt_choice("New status", STATUSES)
                update_status(iid, status)
                print(colorize("Updated.", C.GREEN))

            elif choice == "5":
                iid = int(prompt("Incident ID", required=True))
                ioc_type = prompt_choice("IOC type", IOC_TYPES)
                value = prompt("Value", required=True)
                desc = prompt("Description", default="")
                add_ioc(iid, ioc_type, value, desc or None)
                print(colorize("IOC added.", C.GREEN))

            elif choice == "6":
                iid = int(prompt("Incident ID", required=True))
                note = prompt("Note", required=True)
                author = prompt("Author", default="")
                add_note(iid, note, author or None)
                print(colorize("Note added.", C.GREEN))

            elif choice == "7":
                term = prompt("Search term", required=True)
                incidents, ioc_matches = search(term)
                print_incident_table(incidents)
                for ioc in ioc_matches:
                    print(f"  [{ioc['ioc_type']}] {ioc['value']} "
                          f"-> incident #{ioc['incident_id']}")

            elif choice == "8":
                print_stats(stats())

            elif choice == "9":
                fmt = prompt_choice("Format", ["csv", "json"], default="json")
                out = prompt("Output filename", default=f"incidents_export.{fmt}")
                path = export_data(fmt, out)
                print(colorize(f"Exported to {path}", C.GREEN))

            elif choice == "0":
                print("Goodbye.")
                break
            else:
                print("Invalid option.")
        except ValueError as e:
            print(colorize(f"Error: {e}", C.RED))
        except KeyboardInterrupt:
            print("\nGoodbye.")
            break


if __name__ == "__main__":
    run_cli(sys.argv[1:])
