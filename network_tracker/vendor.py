import logging

logger = logging.getLogger(__name__)

_manuf = None


def _get_manuf():
    global _manuf
    if _manuf is None:
        try:
            from scapy.libs.manuf import manuf
            _manuf = manuf
        except Exception as exc:
            logger.warning("Could not load Scapy manuf database: %s", exc)
            _manuf = False
    return _manuf if _manuf is not False else None


def lookup(mac: str) -> str | None:
    db = _get_manuf()
    if db is None:
        return None
    try:
        return db.getmanuf(mac)
    except Exception:
        return None
