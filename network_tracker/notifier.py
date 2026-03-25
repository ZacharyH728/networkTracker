import logging
from datetime import datetime

import httpx

from .events import JoinEvent, LeaveEvent

logger = logging.getLogger(__name__)

_BOT_API = "https://api.telegram.org/bot{token}/sendMessage"


def notify_join(
    token: str,
    chat_id: str,
    event: JoinEvent,
    aliases: list[dict],
    label: str | None = None,
    thread_id: str | None = None,
) -> None:
    header = f"<b>[NETWORK] {label} joined</b>" if label else "<b>[NETWORK] Device joined</b>"
    lines = [
        header,
        f"IP:       {event.ip}",
        f"MAC:      {event.mac}",
    ]
    if event.vendor:
        lines.append(f"Vendor:   {event.vendor}")
    if event.hostname:
        lines.append(f"Hostname: {event.hostname}")
    lines.append(f"Time:     {_now_utc()}")
    if aliases:
        best = aliases[0]
        lines.append(
            f"\n<i>(likely same device as {best['mac']}, "
            f"confidence {best['confidence']:.0%}, "
            f"first seen {best['first_seen'][:10]})</i>"
        )
    _send(token, chat_id, "\n".join(lines), thread_id=thread_id)


def notify_leave(
    token: str,
    chat_id: str,
    event: LeaveEvent,
    aliases: list[dict],
    now: datetime,
    label: str | None = None,
    thread_id: str | None = None,
) -> None:
    header = f"<b>[NETWORK] {label} left</b>" if label else "<b>[NETWORK] Device left</b>"
    duration = _duration(event.first_seen, now)
    lines = [
        header,
        f"IP:       {event.ip}",
        f"MAC:      {event.mac}",
    ]
    if event.hostname:
        lines.append(f"Hostname: {event.hostname}")
    if duration:
        lines.append(f"Online for: {duration}")
    lines.append(f"Time:     {_now_utc()}")
    if aliases:
        best = aliases[0]
        lines.append(
            f"\n<i>(likely same device as {best['mac']}, "
            f"confidence {best['confidence']:.0%})</i>"
        )
    _send(token, chat_id, "\n".join(lines), thread_id=thread_id)


def _send(token: str, chat_id: str, text: str, thread_id: str | None = None) -> None:
    if not token or not chat_id:
        logger.warning("Telegram not configured — skipping notification")
        return
    payload: dict = {"chat_id": chat_id, "text": text, "parse_mode": "HTML"}
    if thread_id:
        payload["message_thread_id"] = int(thread_id)
    try:
        resp = httpx.post(
            _BOT_API.format(token=token),
            json=payload,
            timeout=10,
        )
        resp.raise_for_status()
    except Exception as exc:
        logger.error("Telegram notification failed: %s", exc)


def _now_utc() -> str:
    return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")


def _duration(first_seen_ts: str, now: datetime) -> str | None:
    try:
        start = datetime.strptime(first_seen_ts, "%Y-%m-%dT%H:%M:%SZ")
        delta = now - start
        total = int(delta.total_seconds())
        if total < 60:
            return f"{total}s"
        elif total < 3600:
            return f"{total // 60}m"
        else:
            h = total // 3600
            m = (total % 3600) // 60
            return f"{h}h {m}m" if m else f"{h}h"
    except Exception:
        return None
