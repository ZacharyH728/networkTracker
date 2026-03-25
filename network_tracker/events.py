from datetime import datetime
from typing import NamedTuple

from .scanner import ScanResult


class JoinEvent(NamedTuple):
    mac: str
    ip: str
    hostname: str | None
    vendor: str | None


class LeaveEvent(NamedTuple):
    mac: str
    ip: str
    hostname: str | None
    first_seen: str
    last_seen: str


def _resolve_grace(vendor: str | None, vendor_graces: dict, default: int) -> int:
    """Resolve effective grace period for a device based on its vendor."""
    if not vendor or not vendor_graces:
        return default
    vendor_lower = vendor.lower()
    for prefix, grace in vendor_graces.items():
        if vendor_lower.startswith(prefix):
            return grace
    return default


def compute_events(
    scan_results: list[ScanResult],
    online_devices: dict,                    # mac -> device row dict (from db.get_online_devices)
    offline_grace: int,                      # default grace period in seconds
    now: datetime,
    vendor_lookup,                           # callable(mac) -> str | None
    vendor_graces: dict[str, int] | None = None,  # vendor prefix -> override grace period
) -> tuple[list[JoinEvent], list[LeaveEvent]]:
    scan_macs = {r.mac for r in scan_results}
    scan_by_mac = {r.mac: r for r in scan_results}

    joins: list[JoinEvent] = []
    for result in scan_results:
        if result.mac not in online_devices:
            joins.append(JoinEvent(
                mac=result.mac,
                ip=result.ip,
                hostname=result.hostname,
                vendor=vendor_lookup(result.mac),
            ))

    leaves: list[LeaveEvent] = []
    for mac, dev in online_devices.items():
        if mac in scan_macs:
            continue
        last_seen_dt = _parse_ts(dev["last_seen"])
        if last_seen_dt is None:
            continue
        seconds_absent = (now - last_seen_dt).total_seconds()
        grace = _resolve_grace(dev.get("vendor"), vendor_graces or {}, offline_grace)
        if seconds_absent >= grace:
            leaves.append(LeaveEvent(
                mac=mac,
                ip=dev["ip"],
                hostname=dev.get("hostname"),
                first_seen=dev["first_seen"],
                last_seen=dev["last_seen"],
            ))

    return joins, leaves


def _parse_ts(ts: str) -> datetime | None:
    try:
        return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        return None
