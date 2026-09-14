"""SQLite storage for scans and findings. Stdlib sqlite3, zero config."""

from __future__ import annotations

import datetime as _dt
import json
import os
import pathlib
import sqlite3
import threading

from .models import Finding, ScanRecord

DEFAULT_DB = pathlib.Path(os.environ.get("SIBAT_DB", pathlib.Path.home() / ".sibat" / "sibat.db"))

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  target TEXT NOT NULL,
  scope_name TEXT NOT NULL,
  started TEXT NOT NULL,
  finished TEXT NOT NULL,
  stats TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS findings(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  category TEXT NOT NULL,
  host TEXT NOT NULL,
  port INTEGER,
  severity TEXT NOT NULL,
  title TEXT NOT NULL,
  detail TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
"""


def utcnow() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


class Store:
    def __init__(self, path: pathlib.Path | str | None = None):
        self.path = pathlib.Path(path) if path else DEFAULT_DB
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # threaded servers (the operator dashboard) share one Store across
        # request threads: allow cross-thread use and serialize all access.
        self.conn = sqlite3.connect(self.path, check_same_thread=False)
        self._lock = threading.Lock()
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(_SCHEMA)
        self.conn.commit()

    # --------------------------------------------------------------- write

    def save_scan(self, target: str, scope_name: str, started: str,
                  findings: list[Finding], stats: dict) -> int:
        with self._lock:
            finished = utcnow()
            cur = self.conn.execute(
                "INSERT INTO scans(target, scope_name, started, finished, stats) VALUES (?,?,?,?,?)",
                (target, scope_name, started, finished, json.dumps(stats)),
            )
            scan_id = int(cur.lastrowid)
            self.conn.executemany(
                "INSERT INTO findings(scan_id, category, host, port, severity, title, detail)"
                " VALUES (?,?,?,?,?,?,?)",
                [(scan_id, f.category, f.host, f.port, f.severity, f.title, f.detail) for f in findings],
            )
            self.conn.commit()
        return scan_id

    # ---------------------------------------------------------------- read

    def list_scans(self) -> list[dict]:
        with self._lock:
            rows = self.conn.execute(
                "SELECT id, target, scope_name, started, finished, stats FROM scans ORDER BY id DESC"
            ).fetchall()
        return [dict(r) for r in rows]

    def get_record(self, scan_id: int) -> ScanRecord | None:
        with self._lock:
            row = self.conn.execute(
                "SELECT id, target, scope_name, started, finished, stats FROM scans WHERE id=?",
                (scan_id,),
            ).fetchone()
            if row is None:
                return None
            frows = self.conn.execute(
                "SELECT category, host, port, severity, title, detail FROM findings"
                " WHERE scan_id=? ORDER BY id",
                (scan_id,),
            ).fetchall()
        findings = [Finding(**dict(r)) for r in frows]
        return ScanRecord(
            scan_id=row["id"], target=row["target"], scope_name=row["scope_name"],
            started=row["started"], finished=row["finished"],
            stats=json.loads(row["stats"]), findings=findings,
        )

    def close(self) -> None:
        self.conn.close()
