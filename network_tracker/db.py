import sqlite3
import pathlib
from datetime import datetime


def initialize(db_path: str) -> sqlite3.Connection:
    pathlib.Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    _create_schema(conn)
    _migrate(conn)
    return conn


def _create_schema(conn: sqlite3.Connection) -> None:
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS devices (
            mac        TEXT PRIMARY KEY,
            ip         TEXT NOT NULL,
            hostname   TEXT,
            vendor     TEXT,
            first_seen TEXT NOT NULL,
            last_seen  TEXT NOT NULL,
            is_online  INTEGER NOT NULL DEFAULT 0,
            label      TEXT,
            notes      TEXT
        );

        CREATE TABLE IF NOT EXISTS events (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            mac        TEXT NOT NULL,
            ip         TEXT NOT NULL,
            event_type TEXT NOT NULL CHECK(event_type IN ('join', 'leave')),
            timestamp  TEXT NOT NULL,
            hostname   TEXT,
            FOREIGN KEY (mac) REFERENCES devices(mac)
        );

        CREATE TABLE IF NOT EXISTS mac_aliases (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            mac_a      TEXT NOT NULL,
            mac_b      TEXT NOT NULL,
            reason     TEXT,
            confidence REAL DEFAULT 0.5,
            first_seen TEXT NOT NULL,
            UNIQUE(mac_a, mac_b)
        );

        CREATE TABLE IF NOT EXISTS mac_ip_history (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            mac        TEXT NOT NULL,
            ip         TEXT NOT NULL,
            first_seen TEXT NOT NULL,
            last_seen  TEXT NOT NULL,
            UNIQUE(mac, ip)
        );

        CREATE TABLE IF NOT EXISTS metadata (
            key   TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_events_mac     ON events(mac);
        CREATE INDEX IF NOT EXISTS idx_events_ts      ON events(timestamp);
        CREATE INDEX IF NOT EXISTS idx_mac_ip_hist_ip ON mac_ip_history(ip);
        CREATE INDEX IF NOT EXISTS idx_devices_ip     ON devices(ip);
    """)
    conn.commit()


def _migrate(conn: sqlite3.Connection) -> None:
    # Add label column to existing databases that predate this feature
    try:
        conn.execute("ALTER TABLE devices ADD COLUMN label TEXT")
        conn.commit()
    except sqlite3.OperationalError:
        pass  # column already exists

    try:
        conn.execute("ALTER TABLE devices ADD COLUMN hidden INTEGER NOT NULL DEFAULT 0")
        conn.commit()
    except sqlite3.OperationalError:
        pass  # column already exists


def upsert_device(
    conn: sqlite3.Connection,
    mac: str,
    ip: str,
    hostname: str | None,
    vendor: str | None,
    now: datetime,
) -> None:
    ts = _ts(now)
    conn.execute(
        """
        INSERT INTO devices (mac, ip, hostname, vendor, first_seen, last_seen, is_online)
        VALUES (?, ?, ?, ?, ?, ?, 1)
        ON CONFLICT(mac) DO UPDATE SET
            ip        = excluded.ip,
            hostname  = COALESCE(excluded.hostname, hostname),
            vendor    = COALESCE(excluded.vendor, vendor),
            last_seen = excluded.last_seen,
            is_online = 1
        """,
        (mac, ip, hostname, vendor, ts, ts),
    )


def set_offline(conn: sqlite3.Connection, mac: str, now: datetime) -> None:
    conn.execute(
        "UPDATE devices SET is_online = 0, last_seen = ? WHERE mac = ?",
        (_ts(now), mac),
    )


def log_event(
    conn: sqlite3.Connection,
    mac: str,
    ip: str,
    event_type: str,
    timestamp: datetime,
    hostname: str | None,
) -> None:
    conn.execute(
        "INSERT INTO events (mac, ip, event_type, timestamp, hostname) VALUES (?,?,?,?,?)",
        (mac, ip, event_type, _ts(timestamp), hostname),
    )


def get_online_devices(conn: sqlite3.Connection) -> dict:
    rows = conn.execute(
        "SELECT mac, ip, hostname, vendor, first_seen, last_seen FROM devices WHERE is_online = 1"
    ).fetchall()
    return {row["mac"]: dict(row) for row in rows}


def upsert_mac_ip_history(
    conn: sqlite3.Connection, mac: str, ip: str, now: datetime
) -> None:
    ts = _ts(now)
    conn.execute(
        """
        INSERT INTO mac_ip_history (mac, ip, first_seen, last_seen)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(mac, ip) DO UPDATE SET last_seen = excluded.last_seen
        """,
        (mac, ip, ts, ts),
    )


def find_recent_macs_for_ip(
    conn: sqlite3.Connection, ip: str, since_ts: str, exclude_mac: str
) -> list[str]:
    rows = conn.execute(
        """
        SELECT mac FROM mac_ip_history
        WHERE ip = ? AND last_seen >= ? AND mac != ?
        """,
        (ip, since_ts, exclude_mac),
    ).fetchall()
    return [row["mac"] for row in rows]


def find_macs_by_hostname(
    conn: sqlite3.Connection, hostname: str, exclude_mac: str
) -> list[str]:
    if not hostname:
        return []
    rows = conn.execute(
        "SELECT mac FROM devices WHERE hostname = ? AND mac != ?",
        (hostname, exclude_mac),
    ).fetchall()
    return [row["mac"] for row in rows]


def upsert_alias(
    conn: sqlite3.Connection,
    mac_a: str,
    mac_b: str,
    reason: str,
    confidence_delta: float,
    now: datetime,
) -> None:
    # Normalise ordering so (a,b) and (b,a) don't create duplicates
    if mac_a > mac_b:
        mac_a, mac_b = mac_b, mac_a
    ts = _ts(now)
    conn.execute(
        """
        INSERT INTO mac_aliases (mac_a, mac_b, reason, confidence, first_seen)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(mac_a, mac_b) DO UPDATE SET
            confidence = MIN(0.95, confidence + ?),
            reason     = excluded.reason
        """,
        (mac_a, mac_b, reason, min(0.5 + confidence_delta, 0.95), ts, confidence_delta),
    )


def get_aliases_for_mac(
    conn: sqlite3.Connection, mac: str, min_confidence: float = 0.8
) -> list[dict]:
    rows = conn.execute(
        """
        SELECT mac_a, mac_b, confidence, first_seen FROM mac_aliases
        WHERE (mac_a = ? OR mac_b = ?) AND confidence >= ?
        ORDER BY confidence DESC
        """,
        (mac, mac, min_confidence),
    ).fetchall()
    result = []
    for row in rows:
        other = row["mac_b"] if row["mac_a"] == mac else row["mac_a"]
        result.append(
            {"mac": other, "confidence": row["confidence"], "first_seen": row["first_seen"]}
        )
    return result


def get_last_leave_time(conn: sqlite3.Connection, mac: str) -> str | None:
    """Return the timestamp of the most recent leave event for this MAC, or None."""
    row = conn.execute(
        "SELECT timestamp FROM events WHERE mac = ? AND event_type = 'leave' "
        "ORDER BY timestamp DESC LIMIT 1",
        (mac,),
    ).fetchone()
    return row["timestamp"] if row else None


def get_device_first_seen(conn: sqlite3.Connection, mac: str) -> str | None:
    row = conn.execute(
        "SELECT first_seen FROM devices WHERE mac = ?", (mac,)
    ).fetchone()
    return row["first_seen"] if row else None


def set_label(conn: sqlite3.Connection, mac: str, label: str | None) -> None:
    conn.execute("UPDATE devices SET label = ? WHERE mac = ?", (label, mac))


def get_label(conn: sqlite3.Connection, mac: str) -> str | None:
    row = conn.execute("SELECT label FROM devices WHERE mac = ?", (mac,)).fetchone()
    return row["label"] if row else None


def propagate_label(conn: sqlite3.Connection, mac_a: str, mac_b: str) -> None:
    """Copy label from whichever MAC has one to the one that doesn't."""
    label_a = get_label(conn, mac_a)
    label_b = get_label(conn, mac_b)
    if label_a and not label_b:
        set_label(conn, mac_b, label_a)
    elif label_b and not label_a:
        set_label(conn, mac_a, label_b)


def set_meta(conn: sqlite3.Connection, key: str, value: str) -> None:
    conn.execute(
        "INSERT INTO metadata (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (key, value),
    )


def get_meta(conn: sqlite3.Connection, key: str) -> str | None:
    row = conn.execute("SELECT value FROM metadata WHERE key = ?", (key,)).fetchone()
    return row["value"] if row else None


def get_all_devices(conn: sqlite3.Connection) -> list[dict]:
    rows = conn.execute(
        "SELECT mac, ip, hostname, vendor, label, is_online, last_seen FROM devices "
        "ORDER BY is_online DESC, last_seen DESC"
    ).fetchall()
    return [dict(row) for row in rows]


def _ts(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
