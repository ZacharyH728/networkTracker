import logging
import threading
import time
from datetime import datetime

from . import config, db, scanner, vendor, events, mac_history, notifier

# MACs that the sniffer thread has already sent a join notification for.
# The main scan loop checks this to avoid sending a duplicate notification
# if the scanner also happens to detect the same device in its next cycle.
_sniff_notified: set[str] = set()
_sniff_lock = threading.Lock()


def setup_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%SZ",
    )


def _recently_left(conn, mac: str, now: datetime, window_seconds: int) -> bool:
    """Return True if this MAC had a leave event within the last window_seconds."""
    last_leave = db.get_last_leave_time(conn, mac)
    if not last_leave:
        return False
    try:
        leave_dt = datetime.strptime(last_leave, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return False
    return (now - leave_dt).total_seconds() < window_seconds


def _run_sniffer(db_path, bot_token, chat_id, thread_id, scan_interval, rejoin_window):
    """Background thread: passively sniff ARP and fire join notifications immediately."""
    log = logging.getLogger(__name__ + ".sniffer")
    # Own connection — WAL mode allows concurrent reads/writes from multiple connections.
    conn = db.initialize(db_path)
    log.info("ARP sniffer started")

    def on_arp(ip, mac):
        now = datetime.utcnow()
        row = conn.execute(
            "SELECT is_online FROM devices WHERE mac = ?", (mac,)
        ).fetchone()

        if row and row["is_online"]:
            # Device already online — refresh last_seen so the scanner's grace
            # period doesn't expire just because the active scan missed it.
            with conn:
                conn.execute(
                    "UPDATE devices SET last_seen = ?, ip = ? WHERE mac = ?",
                    (now.strftime("%Y-%m-%dT%H:%M:%SZ"), ip, mac),
                )
            return

        v = vendor.lookup(mac)
        hostname = scanner._reverse_dns(ip)
        recently_left = _recently_left(conn, mac, now, rejoin_window)

        with conn:
            db.upsert_device(conn, mac, ip, hostname, v, now)
            db.upsert_mac_ip_history(conn, mac, ip, now)
            mac_history.check_and_record_aliases(conn, ip, mac, now, scan_interval, hostname)
            if not recently_left:
                db.log_event(conn, mac, ip, "join", now, hostname)

        label = db.get_label(conn, mac)
        log.info("JOIN (sniff) %s  %s  %s%s", mac, ip, hostname or "",
                 f"  [{label}]" if label else "")

        if recently_left:
            log.info("JOIN (sniff) %s suppressed — rejoined within %ds of leaving", mac, rejoin_window)
            with _sniff_lock:
                _sniff_notified.add(mac)  # prevent scanner from notifying too
            return

        aliases = db.get_aliases_for_mac(conn, mac)
        j = events.JoinEvent(mac=mac, ip=ip, hostname=hostname, vendor=v)
        with _sniff_lock:
            _sniff_notified.add(mac)
        notifier.notify_join(bot_token, chat_id, j, aliases, label=label, thread_id=thread_id)

    try:
        scanner.sniff_arp(on_arp)
    except PermissionError:
        log.warning("ARP sniffing requires root/NET_RAW — passive detection disabled")
    except Exception:
        log.exception("ARP sniffer failed")


def main() -> None:
    cfg = config.load()

    setup_logging(cfg.get("logging", "level", fallback="INFO"))
    log = logging.getLogger(__name__)

    db_path = cfg.get("database", "path", fallback="data/tracker.db")
    conn = db.initialize(db_path)
    log.info("Database ready at %s", db_path)

    cidr          = cfg.get("network", "cidr", fallback="192.168.1.0/24")
    scan_interval = cfg.getint("network", "scan_interval", fallback=60)
    scan_timeout  = cfg.getfloat("network", "scan_timeout", fallback=3.0)
    offline_grace  = cfg.getint("network", "offline_grace", fallback=180)
    rejoin_window  = cfg.getint("network", "rejoin_window", fallback=offline_grace * 2)
    bot_token      = cfg.get("telegram", "bot_token", fallback="")
    chat_id       = cfg.get("telegram", "chat_id", fallback="")
    thread_id     = cfg.get("telegram", "thread_id", fallback="") or None

    # Load per-vendor grace period overrides
    vendor_graces = {}
    if cfg.has_section("vendor_grace"):
        for prefix, val in cfg.items("vendor_grace"):
            try:
                vendor_graces[prefix.lower()] = int(val)
            except ValueError:
                log.warning("Invalid vendor_grace value for %s: %s", prefix, val)

    log.info("Starting network tracker | CIDR=%s | interval=%ds | grace=%ds",
             cidr, scan_interval, offline_grace)
    if vendor_graces:
        log.info("Per-vendor grace periods: %s", vendor_graces)

    # Start passive ARP sniffer in a daemon thread for instant join detection.
    sniffer = threading.Thread(
        target=_run_sniffer,
        args=(db_path, bot_token, chat_id, thread_id, scan_interval, rejoin_window),
        daemon=True,
        name="arp-sniffer",
    )
    sniffer.start()

    while True:
        try:
            now = datetime.utcnow()
            results = scanner.scan(cidr, timeout=scan_timeout)
            log.info("Scan complete: %d device(s) found", len(results))

            online_before = db.get_online_devices(conn)
            joins, leaves = events.compute_events(
                results, online_before, offline_grace, now, vendor.lookup,
                vendor_graces=vendor_graces
            )

            with conn:
                # Update all seen devices
                for r in results:
                    v = vendor.lookup(r.mac)
                    db.upsert_device(conn, r.mac, r.ip, r.hostname, v, now)
                    db.upsert_mac_ip_history(conn, r.mac, r.ip, now)
                    mac_history.check_and_record_aliases(
                        conn, r.ip, r.mac, now, scan_interval, r.hostname
                    )

                # Suppress notifications for join/leave pairs that are high-confidence
                # aliases of each other — the device just changed its address.
                leave_macs = {l.mac for l in leaves}
                suppressed_joins: set[str] = set()
                suppressed_leaves: set[str] = set()
                for j in joins:
                    for alias in db.get_aliases_for_mac(conn, j.mac):
                        if alias["mac"] in leave_macs:
                            suppressed_joins.add(j.mac)
                            suppressed_leaves.add(alias["mac"])
                            log.info(
                                "Address change detected: %s -> %s (confidence %.0f%%) — suppressing notifications",
                                alias["mac"], j.mac, alias["confidence"] * 100,
                            )

                # Process joins
                for j in joins:
                    recently_left = _recently_left(conn, j.mac, now, rejoin_window)
                    if not recently_left:
                        db.log_event(conn, j.mac, j.ip, "join", now, j.hostname)
                    label = db.get_label(conn, j.mac)
                    log.info("JOIN  %s  %s  %s%s", j.mac, j.ip, j.hostname or "",
                             f"  [{label}]" if label else "")
                    if j.mac in suppressed_joins:
                        continue
                    # Skip if the sniffer already sent a notification for this device.
                    with _sniff_lock:
                        if j.mac in _sniff_notified:
                            _sniff_notified.discard(j.mac)
                            log.debug("JOIN %s already notified by sniffer — skipping", j.mac)
                            continue
                    # Skip if the device rejoined too soon after leaving (same MAC, flap).
                    if recently_left:
                        log.info("JOIN %s suppressed — rejoined within %ds of leaving", j.mac, rejoin_window)
                        continue
                    aliases = db.get_aliases_for_mac(conn, j.mac)
                    notifier.notify_join(bot_token, chat_id, j, aliases, label=label, thread_id=thread_id)

                # Process leaves
                for l in leaves:
                    db.set_offline(conn, l.mac, now)
                    db.log_event(conn, l.mac, l.ip, "leave", now, l.hostname)
                    label = db.get_label(conn, l.mac)
                    log.info("LEAVE %s  %s  %s%s", l.mac, l.ip, l.hostname or "",
                             f"  [{label}]" if label else "")
                    if l.mac not in suppressed_leaves:
                        aliases = db.get_aliases_for_mac(conn, l.mac)
                        notifier.notify_leave(bot_token, chat_id, l, aliases, now, label=label, thread_id=thread_id)

            with conn:
                db.set_meta(conn, 'last_scan', db._ts(now))

            elapsed = (datetime.utcnow() - now).total_seconds()
            sleep_for = max(0.0, scan_interval - elapsed)
            log.debug("Cycle done in %.1fs, sleeping %.1fs", elapsed, sleep_for)
            time.sleep(sleep_for)

        except KeyboardInterrupt:
            log.info("Shutting down.")
            break
        except Exception:
            log.exception("Scan cycle failed — retrying in %ds", scan_interval)
            time.sleep(scan_interval)


if __name__ == "__main__":
    main()
