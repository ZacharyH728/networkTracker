"""
Device label management CLI.

Usage (from the project root or inside the container):
  python -m network_tracker.cli list
  python -m network_tracker.cli label <mac> "<nickname>"
  python -m network_tracker.cli unlabel <mac>
"""

import sys

from . import config, db


def _get_conn():
    cfg = config.load()
    db_path = cfg.get("database", "path", fallback="data/tracker.db")
    return db.initialize(db_path)


def cmd_list() -> None:
    conn = _get_conn()
    devices = db.get_all_devices(conn)
    if not devices:
        print("No devices in database yet.")
        return

    # Column widths
    w_mac    = 17
    w_ip     = 15
    w_label  = 22
    w_vendor = 20
    w_status = 7

    header = (
        f"{'MAC':<{w_mac}}  {'IP':<{w_ip}}  {'Label':<{w_label}}  "
        f"{'Vendor':<{w_vendor}}  {'Status':<{w_status}}  Last Seen"
    )
    print(header)
    print("-" * len(header))

    for d in devices:
        status = "online" if d["is_online"] else "offline"
        label  = d["label"] or "(unlabeled)"
        vendor = (d["vendor"] or "")[:w_vendor]
        print(
            f"{d['mac']:<{w_mac}}  {d['ip']:<{w_ip}}  {label:<{w_label}}  "
            f"{vendor:<{w_vendor}}  {status:<{w_status}}  {d['last_seen']}"
        )


def cmd_label(mac: str, label: str) -> None:
    mac = mac.lower().strip()
    conn = _get_conn()
    existing = db.get_label(conn, mac)
    with conn:
        db.set_label(conn, mac, label)
    if existing:
        print(f"Updated label for {mac}: '{existing}' → '{label}'")
    else:
        print(f"Set label for {mac}: '{label}'")


def cmd_unlabel(mac: str) -> None:
    mac = mac.lower().strip()
    conn = _get_conn()
    existing = db.get_label(conn, mac)
    if not existing:
        print(f"No label set for {mac}.")
        return
    with conn:
        db.set_label(conn, mac, None)
    print(f"Removed label '{existing}' from {mac}.")


def main() -> None:
    args = sys.argv[1:]
    if not args:
        print(__doc__)
        sys.exit(0)

    command = args[0]

    if command == "list":
        cmd_list()
    elif command == "label":
        if len(args) < 3:
            print("Usage: cli.py label <mac> \"<nickname>\"")
            sys.exit(1)
        cmd_label(args[1], args[2])
    elif command == "unlabel":
        if len(args) < 2:
            print("Usage: cli.py unlabel <mac>")
            sys.exit(1)
        cmd_unlabel(args[1])
    else:
        print(f"Unknown command: {command}")
        print(__doc__)
        sys.exit(1)


if __name__ == "__main__":
    main()
