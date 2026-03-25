import logging
import time
from datetime import datetime

from . import config, db, scanner, vendor, events, mac_history, notifier


def setup_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%SZ",
    )


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
    offline_grace = cfg.getint("network", "offline_grace", fallback=180)
    bot_token     = cfg.get("telegram", "bot_token", fallback="")
    chat_id       = cfg.get("telegram", "chat_id", fallback="")
    thread_id     = cfg.get("telegram", "thread_id", fallback="") or None

    log.info("Starting network tracker | CIDR=%s | interval=%ds | grace=%ds",
             cidr, scan_interval, offline_grace)

    while True:
        try:
            now = datetime.utcnow()
            results = scanner.scan(cidr, timeout=scan_timeout)
            log.info("Scan complete: %d device(s) found", len(results))

            online_before = db.get_online_devices(conn)
            joins, leaves = events.compute_events(
                results, online_before, offline_grace, now, vendor.lookup
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

                # Process joins
                for j in joins:
                    db.log_event(conn, j.mac, j.ip, "join", now, j.hostname)
                    label = db.get_label(conn, j.mac)
                    log.info("JOIN  %s  %s  %s%s", j.mac, j.ip, j.hostname or "",
                             f"  [{label}]" if label else "")
                    aliases = db.get_aliases_for_mac(conn, j.mac)
                    notifier.notify_join(bot_token, chat_id, j, aliases, label=label, thread_id=thread_id)

                # Process leaves
                for l in leaves:
                    db.set_offline(conn, l.mac, now)
                    db.log_event(conn, l.mac, l.ip, "leave", now, l.hostname)
                    label = db.get_label(conn, l.mac)
                    log.info("LEAVE %s  %s  %s%s", l.mac, l.ip, l.hostname or "",
                             f"  [{label}]" if label else "")
                    aliases = db.get_aliases_for_mac(conn, l.mac)
                    notifier.notify_leave(bot_token, chat_id, l, aliases, now, label=label, thread_id=thread_id)

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
