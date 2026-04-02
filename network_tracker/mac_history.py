import logging
from datetime import datetime, timedelta
from . import db

logger = logging.getLogger(__name__)



def check_and_record_aliases(
    conn,
    ip: str,
    mac: str,
    now: datetime,
    scan_interval: int,
    hostname: str | None = None,
) -> None:
    # Look for other MACs that recently used the same IP (rotation signal)
    window = now - timedelta(seconds=scan_interval * 2)
    window_ts = window.strftime("%Y-%m-%dT%H:%M:%SZ")

    sibling_macs = db.find_recent_macs_for_ip(conn, ip, window_ts, exclude_mac=mac)
    for sibling in sibling_macs:
        logger.info(
            "MAC rotation candidate: %s and %s both used IP %s", mac, sibling, ip
        )
        db.upsert_alias(conn, mac, sibling, "same_ip_sequential", 0.1, now)

    # Look for devices with the same hostname (another rotation signal)
    if hostname:
        hostname_siblings = db.find_macs_by_hostname(conn, hostname, exclude_mac=mac)
        for sibling in hostname_siblings:
            logger.info(
                "Hostname rotation candidate: %s and %s share hostname %s",
                mac, sibling, hostname,
            )
            db.upsert_alias(conn, mac, sibling, "same_hostname", 0.2, now)
