"""Small SQLite persistence layer. Every operation opens and closes its own connection.

This makes background scan workers safe in development. PostgreSQL can replace this
module at deployment without changing the presentation or scanning layers.
"""
from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterator

from app.config import settings


def utcnow() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


@contextmanager
def connection() -> Iterator[sqlite3.Connection]:
    settings.database_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(settings.database_path, timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  email TEXT NOT NULL COLLATE NOCASE UNIQUE,
  password_hash TEXT NOT NULL,
  account_type TEXT NOT NULL CHECK(account_type IN ('student','developer','organization')),
  institution TEXT,
  course_year TEXT,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS applications (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  target_url TEXT NOT NULL,
  repository_url TEXT,
  source_filename TEXT,
  source_sha256 TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_applications_user ON applications(user_id);
CREATE TABLE IF NOT EXISTS scans (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  application_id INTEGER NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
  status TEXT NOT NULL CHECK(status IN ('queued','running','completed','failed')),
  authorization_confirmed_at TEXT NOT NULL,
  started_at TEXT,
  completed_at TEXT,
  score INTEGER,
  risk_level TEXT,
  model_version TEXT NOT NULL,
  error_message TEXT,
  summary TEXT
);
CREATE INDEX IF NOT EXISTS idx_scans_application ON scans(application_id, id DESC);
CREATE TABLE IF NOT EXISTS findings (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  category TEXT NOT NULL,
  title TEXT NOT NULL,
  severity TEXT NOT NULL CHECK(severity IN ('critical','high','medium','low','info')),
  evidence TEXT NOT NULL,
  explanation TEXT NOT NULL,
  remediation TEXT NOT NULL,
  effort TEXT NOT NULL CHECK(effort IN ('Easy','Moderate','Advanced')),
  score_impact INTEGER NOT NULL,
  confidence REAL,
  source TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
"""


def initialize() -> None:
    with connection() as conn:
        conn.executescript(SCHEMA)


def one(query: str, parameters: tuple[Any, ...] = ()) -> dict[str, Any] | None:
    with connection() as conn:
        row = conn.execute(query, parameters).fetchone()
        return dict(row) if row else None


def all_rows(query: str, parameters: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
    with connection() as conn:
        return [dict(row) for row in conn.execute(query, parameters).fetchall()]


def execute(query: str, parameters: tuple[Any, ...] = ()) -> int:
    with connection() as conn:
        cursor = conn.execute(query, parameters)
        return int(cursor.lastrowid)


def create_user(name: str, email: str, password_hash: str, account_type: str, institution: str | None, course_year: str | None) -> int:
    return execute(
        "INSERT INTO users(name,email,password_hash,account_type,institution,course_year,created_at) VALUES (?,?,?,?,?,?,?)",
        (name.strip(), email.strip().lower(), password_hash, account_type, institution or None, course_year or None, utcnow()),
    )


def create_application(user_id: int, name: str, target_url: str, repository_url: str | None, source_filename: str | None, source_sha256: str | None) -> int:
    now = utcnow()
    return execute(
        "INSERT INTO applications(user_id,name,target_url,repository_url,source_filename,source_sha256,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?)",
        (user_id, name.strip(), target_url.strip(), repository_url or None, source_filename or None, source_sha256 or None, now, now),
    )


def get_owned_application(application_id: int, user_id: int) -> dict[str, Any] | None:
    return one("SELECT * FROM applications WHERE id=? AND user_id=?", (application_id, user_id))


def list_applications(user_id: int) -> list[dict[str, Any]]:
    return all_rows(
        """SELECT a.*, s.score AS latest_score, s.risk_level AS latest_risk, s.completed_at AS latest_scan_at
           FROM applications a
           LEFT JOIN scans s ON s.id=(SELECT id FROM scans WHERE application_id=a.id AND status='completed' ORDER BY id DESC LIMIT 1)
           WHERE a.user_id=? ORDER BY a.updated_at DESC""",
        (user_id,),
    )


def list_scans(application_id: int) -> list[dict[str, Any]]:
    return all_rows("SELECT * FROM scans WHERE application_id=? ORDER BY id DESC", (application_id,))


def create_scan(application_id: int) -> int:
    return execute(
        "INSERT INTO scans(application_id,status,authorization_confirmed_at,model_version) VALUES (?,?,?,?)",
        (application_id, "queued", utcnow(), "tfidf-logreg-v1"),
    )


def recent_scan_count(user_id: int, since: str) -> int:
    row = one(
        """SELECT COUNT(*) AS count FROM scans s
           JOIN applications a ON a.id=s.application_id
           WHERE a.user_id=? AND s.authorization_confirmed_at>=?""",
        (user_id, since),
    )
    return int(row["count"]) if row else 0

def update_scan(scan_id: int, **fields: Any) -> None:
    if not fields:
        return
    names = ", ".join(f"{key}=?" for key in fields)
    execute(f"UPDATE scans SET {names} WHERE id=?", tuple(fields.values()) + (scan_id,))


def get_owned_scan(scan_id: int, user_id: int) -> dict[str, Any] | None:
    return one(
        """SELECT s.*, a.name AS application_name, a.target_url, a.id AS application_id
           FROM scans s JOIN applications a ON a.id=s.application_id
           WHERE s.id=? AND a.user_id=?""",
        (scan_id, user_id),
    )


def findings_for_scan(scan_id: int) -> list[dict[str, Any]]:
    return all_rows("SELECT * FROM findings WHERE scan_id=? ORDER BY CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END, id", (scan_id,))


def insert_findings(scan_id: int, findings: list[dict[str, Any]]) -> None:
    with connection() as conn:
        conn.executemany(
            """INSERT INTO findings(scan_id,category,title,severity,evidence,explanation,remediation,effort,score_impact,confidence,source)
               VALUES (:scan_id,:category,:title,:severity,:evidence,:explanation,:remediation,:effort,:score_impact,:confidence,:source)""",
            [{**finding, "scan_id": scan_id} for finding in findings],
        )


def delete_owned_application(application_id: int, user_id: int) -> None:
    execute("DELETE FROM applications WHERE id=? AND user_id=?", (application_id, user_id))


def delete_owned_scan(scan_id: int, user_id: int) -> bool:
    with connection() as conn:
        cursor = conn.execute("DELETE FROM scans WHERE id=? AND application_id IN (SELECT id FROM applications WHERE user_id=?)", (scan_id, user_id))
        return cursor.rowcount > 0
