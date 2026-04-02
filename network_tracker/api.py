import os
import sqlite3

from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

DB_PATH = os.environ.get("DB_PATH", "data/tracker.db")

app = FastAPI(title="Network Tracker API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


def get_db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn
    finally:
        conn.close()


@app.get("/api/status")
def get_status(conn: sqlite3.Connection = Depends(get_db)):
    row = conn.execute("SELECT value FROM metadata WHERE key = 'last_scan'").fetchone()
    return {"last_scan": row["value"] if row else None}


@app.get("/api/devices")
def list_devices(conn: sqlite3.Connection = Depends(get_db)):
    rows = conn.execute(
        """
        SELECT
            d.mac, d.ip, d.hostname, d.vendor, d.label, d.hidden,
            d.is_online, d.first_seen, d.last_seen,
            (SELECT timestamp FROM events
             WHERE mac = d.mac AND event_type = 'join'
             ORDER BY timestamp DESC LIMIT 1) AS last_join,
            (SELECT timestamp FROM events
             WHERE mac = d.mac AND event_type = 'leave'
             ORDER BY timestamp DESC LIMIT 1) AS last_leave
        FROM devices d
        ORDER BY d.is_online DESC, d.last_seen DESC
        """
    ).fetchall()
    return [dict(r) for r in rows]


@app.get("/api/devices/{mac}/events")
def device_events(
    mac: str, limit: int = 200, conn: sqlite3.Connection = Depends(get_db)
):
    mac = mac.lower()
    rows = conn.execute(
        "SELECT id, mac, ip, event_type, timestamp, hostname FROM events "
        "WHERE mac = ? ORDER BY timestamp DESC LIMIT ?",
        (mac, limit),
    ).fetchall()
    return [dict(r) for r in rows]


class LabelBody(BaseModel):
    label: str


@app.put("/api/devices/{mac}/label")
def set_label(
    mac: str, body: LabelBody, conn: sqlite3.Connection = Depends(get_db)
):
    mac = mac.lower()
    if not conn.execute("SELECT 1 FROM devices WHERE mac = ?", (mac,)).fetchone():
        raise HTTPException(status_code=404, detail="Device not found")
    label = body.label.strip() or None
    with conn:
        conn.execute("UPDATE devices SET label = ? WHERE mac = ?", (label, mac))
    return {"mac": mac, "label": label}


@app.delete("/api/devices/{mac}/label")
def remove_label(mac: str, conn: sqlite3.Connection = Depends(get_db)):
    mac = mac.lower()
    if not conn.execute("SELECT 1 FROM devices WHERE mac = ?", (mac,)).fetchone():
        raise HTTPException(status_code=404, detail="Device not found")
    with conn:
        conn.execute("UPDATE devices SET label = NULL WHERE mac = ?", (mac,))
    return {"mac": mac, "label": None}


class HiddenBody(BaseModel):
    hidden: bool


@app.put("/api/devices/{mac}/hidden")
def set_hidden(
    mac: str, body: HiddenBody, conn: sqlite3.Connection = Depends(get_db)
):
    mac = mac.lower()
    if not conn.execute("SELECT 1 FROM devices WHERE mac = ?", (mac,)).fetchone():
        raise HTTPException(status_code=404, detail="Device not found")
    with conn:
        conn.execute("UPDATE devices SET hidden = ? WHERE mac = ?", (1 if body.hidden else 0, mac))
    return {"mac": mac, "hidden": body.hidden}
