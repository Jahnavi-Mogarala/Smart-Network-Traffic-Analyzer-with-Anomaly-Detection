"""SQLite connection handling, schema creation and typed settings storage."""
import sqlite3
from contextlib import contextmanager

import config

SCHEMA = """
CREATE TABLE IF NOT EXISTS analyses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_type TEXT NOT NULL,              -- upload | capture | sample
    source_name TEXT NOT NULL,
    created_at TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'queued',  -- queued | processing | completed | failed
    error TEXT,
    total_packets INTEGER NOT NULL DEFAULT 0,
    total_bytes INTEGER NOT NULL DEFAULT 0,
    duration_sec REAL NOT NULL DEFAULT 0,
    unique_src INTEGER NOT NULL DEFAULT 0,
    unique_dst INTEGER NOT NULL DEFAULT 0,
    alert_count INTEGER NOT NULL DEFAULT 0,
    truncated INTEGER NOT NULL DEFAULT 0,
    summary_json TEXT
);
CREATE TABLE IF NOT EXISTS packets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    analysis_id INTEGER NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
    ts REAL NOT NULL,
    src TEXT, dst TEXT, sport INTEGER, dport INTEGER,
    transport TEXT, proto TEXT, length INTEGER,
    flags TEXT, dns_query TEXT, layers TEXT, info TEXT
);
CREATE INDEX IF NOT EXISTS idx_packets_an_ts ON packets(analysis_id, ts);
CREATE INDEX IF NOT EXISTS idx_packets_an_src ON packets(analysis_id, src);
CREATE INDEX IF NOT EXISTS idx_packets_an_dst ON packets(analysis_id, dst);
CREATE INDEX IF NOT EXISTS idx_packets_an_proto ON packets(analysis_id, proto);
CREATE TABLE IF NOT EXISTS protocol_stats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    analysis_id INTEGER NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
    category TEXT NOT NULL,                 -- headline | transport | layer
    name TEXT NOT NULL,
    packets INTEGER NOT NULL,
    bytes INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_pstats_an ON protocol_stats(analysis_id);
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    analysis_id INTEGER NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
    alert_uid TEXT NOT NULL,
    detected_at TEXT NOT NULL,
    event_ts REAL,                          -- packet time the alert refers to
    window_end REAL,
    severity TEXT NOT NULL,                 -- Info | Low | Medium | High
    category TEXT NOT NULL,
    source TEXT, destination TEXT,
    observed TEXT, baseline TEXT,
    explanation TEXT, recommendation TEXT,
    reviewed INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_alerts_an ON alerts(analysis_id);
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
"""


def connect():
    config.INSTANCE_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(config.DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


@contextmanager
def db():
    """Short-lived connection; commits on success, rolls back on error. Thread-safe by design."""
    conn = connect()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db():
    config.UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    with db() as conn:
        conn.executescript(SCHEMA)


# ---------------- settings ----------------
def _coerce(name, raw):
    d = config.SETTINGS_SCHEMA[name]
    kind = d["type"]
    if kind == "str":
        value = str(raw)
        if d["choices"] and value not in d["choices"]:
            raise ValueError(f"{name} must be one of {d['choices']}")
        return value
    if isinstance(raw, bool):
        raise ValueError(f"{name} must be a number")
    try:
        value = int(raw) if kind == "int" else float(raw)
        if kind == "int" and float(raw) != value:
            raise ValueError
    except (TypeError, ValueError):
        raise ValueError(f"{name} must be {'an integer' if kind == 'int' else 'a number'}")
    if (d["min"] is not None and value < d["min"]) or (d["max"] is not None and value > d["max"]):
        raise ValueError(f"{name} must be between {d['min']} and {d['max']}")
    return value


def get_settings():
    values = {k: v["default"] for k, v in config.SETTINGS_SCHEMA.items()}
    with db() as conn:
        for row in conn.execute("SELECT key, value FROM settings"):
            if row["key"] in values:
                try:
                    values[row["key"]] = _coerce(row["key"], row["value"])
                except ValueError:
                    pass                      # ignore corrupted rows, keep default
    return values


def update_settings(updates):
    if not isinstance(updates, dict) or not updates:
        raise ValueError("Request body must be a non-empty JSON object")
    clean = {}
    for key, raw in updates.items():
        if key not in config.SETTINGS_SCHEMA:
            raise ValueError(f"Unknown setting: {key}")
        clean[key] = _coerce(key, raw)
    with db() as conn:
        for key, value in clean.items():
            conn.execute("INSERT INTO settings(key, value) VALUES(?, ?) "
                         "ON CONFLICT(key) DO UPDATE SET value = excluded.value", (key, str(value)))
    return get_settings()


def reset_settings():
    with db() as conn:
        conn.execute("DELETE FROM settings")
    return get_settings()
