"""Персистенция результатов в SQLite и выявление новых открытых сервисов."""

import sqlite3
from datetime import datetime, timezone
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at  TEXT NOT NULL,
    finished_at TEXT,
    targets     TEXT NOT NULL,
    total_open  INTEGER NOT NULL DEFAULT 0,
    new_count   INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS services (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ip          TEXT NOT NULL,
    port        INTEGER NOT NULL,
    proto       TEXT NOT NULL,
    service     TEXT,
    banner      TEXT,
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    UNIQUE (ip, port, proto)
);

CREATE TABLE IF NOT EXISTS findings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ip          TEXT NOT NULL,
    port        INTEGER NOT NULL,
    proto       TEXT NOT NULL,
    service     TEXT,
    banner      TEXT,
    detected_at TEXT NOT NULL,
    scan_id     INTEGER NOT NULL,
    FOREIGN KEY (scan_id) REFERENCES scans (id)
);
"""


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Storage:
    def __init__(self, db_path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as conn:
            conn.executescript(SCHEMA)

    def connect(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    def record_scan(self, targets, banner_results):
        """Сохраняет результаты скана и возвращает (scan_id, новые находки).

        Новой считается тройка (ip, port, proto), которой ещё не было в
        таблице services. Повторно встреченные сервисы только обновляют
        last_seen и баннер.
        """
        moment = now()
        new_findings = []
        with self.connect() as conn:
            cur = conn.execute(
                "INSERT INTO scans (started_at, targets, total_open) VALUES (?, ?, ?)",
                (moment, ", ".join(targets), len(banner_results)),
            )
            scan_id = cur.lastrowid

            for res in banner_results:
                existing = conn.execute(
                    "SELECT id FROM services WHERE ip = ? AND port = ? AND proto = ?",
                    (res.ip, res.port, res.proto),
                ).fetchone()

                if existing is None:
                    conn.execute(
                        "INSERT INTO services "
                        "(ip, port, proto, service, banner, first_seen, last_seen) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?)",
                        (res.ip, res.port, res.proto, res.service, res.banner, moment, moment),
                    )
                    conn.execute(
                        "INSERT INTO findings "
                        "(ip, port, proto, service, banner, detected_at, scan_id) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?)",
                        (res.ip, res.port, res.proto, res.service, res.banner, moment, scan_id),
                    )
                    new_findings.append(res)
                else:
                    conn.execute(
                        "UPDATE services SET service = ?, banner = ?, last_seen = ? "
                        "WHERE id = ?",
                        (res.service, res.banner, moment, existing["id"]),
                    )

            conn.execute(
                "UPDATE scans SET finished_at = ?, new_count = ? WHERE id = ?",
                (now(), len(new_findings), scan_id),
            )
        return scan_id, new_findings

    def get_services(self, limit=500):
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT ip, port, proto, service, banner, first_seen, last_seen "
                "FROM services ORDER BY last_seen DESC, ip LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def get_findings(self, limit=50):
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT ip, port, proto, service, banner, detected_at, scan_id "
                "FROM findings ORDER BY detected_at DESC, id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def get_scans(self, limit=30):
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT id, started_at, finished_at, targets, total_open, new_count "
                "FROM scans ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def get_stats(self):
        with self.connect() as conn:
            hosts = conn.execute("SELECT COUNT(DISTINCT ip) AS n FROM services").fetchone()["n"]
            open_ports = conn.execute("SELECT COUNT(*) AS n FROM services").fetchone()["n"]
            findings = conn.execute("SELECT COUNT(*) AS n FROM findings").fetchone()["n"]
            scans = conn.execute("SELECT COUNT(*) AS n FROM scans").fetchone()["n"]
        return {
            "hosts": hosts,
            "open_ports": open_ports,
            "findings": findings,
            "scans": scans,
        }
