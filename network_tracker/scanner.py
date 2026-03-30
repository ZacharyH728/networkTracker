import socket
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import NamedTuple

logger = logging.getLogger(__name__)


class ScanResult(NamedTuple):
    ip: str
    mac: str
    hostname: str | None


def scan(cidr: str, timeout: float = 3.0) -> list[ScanResult]:
    try:
        return _arp_scan(cidr, timeout)
    except PermissionError:
        logger.warning("ARP scan requires root/NET_RAW — falling back to ARP cache")
        return _arp_cache_fallback()
    except Exception as exc:
        logger.error("Scan failed: %s", exc)
        return []


def _arp_scan(cidr: str, timeout: float) -> list[ScanResult]:
    # Import here so the module loads even if scapy isn't installed yet
    from scapy.layers.l2 import ARP, Ether
    from scapy.sendrecv import srp

    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=cidr)
    answered, _ = srp(pkt, timeout=timeout, verbose=False)

    pairs = [(rcv.psrc, rcv.hwsrc.lower()) for _, rcv in answered]
    hostnames = _bulk_reverse_dns([ip for ip, _ in pairs])

    results = []
    for ip, mac in pairs:
        results.append(ScanResult(ip=ip, mac=mac, hostname=hostnames.get(ip)))

    logger.debug("ARP scan found %d device(s) on %s", len(results), cidr)
    return results


def _bulk_reverse_dns(ips: list[str]) -> dict[str, str | None]:
    results: dict[str, str | None] = {}
    with ThreadPoolExecutor(max_workers=min(32, len(ips) or 1)) as pool:
        futures = {pool.submit(_reverse_dns, ip): ip for ip in ips}
        for future in as_completed(futures):
            ip = futures[future]
            results[ip] = future.result()
    return results


def _reverse_dns(ip: str) -> str | None:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


def sniff_arp(callback) -> None:
    """Passively sniff ARP packets and call callback(ip, mac) for each sender seen.

    Runs indefinitely — intended to be called from a daemon thread.
    Requires root / NET_RAW capability (same as active scanning).
    """
    from scapy.layers.l2 import ARP
    from scapy.sendrecv import sniff as scapy_sniff

    def _handle(pkt):
        if ARP in pkt:
            arp = pkt[ARP]
            # Both ARP requests (op=1) and replies (op=2) carry the sender's real IP/MAC.
            if arp.psrc != "0.0.0.0":
                try:
                    callback(arp.psrc, arp.hwsrc.lower())
                except Exception:
                    pass

    scapy_sniff(filter="arp", prn=_handle, store=False)


def _arp_cache_fallback() -> list[ScanResult]:
    """Parse the system ARP cache (no root required, but may be stale/incomplete)."""
    import subprocess
    results = []
    try:
        output = subprocess.check_output(["arp", "-a"], text=True, timeout=5)
        for line in output.splitlines():
            # macOS/Linux format: hostname (ip) at mac [ether] ...
            parts = line.split()
            if len(parts) < 4:
                continue
            ip = parts[1].strip("()")
            mac_candidate = parts[3].lower()
            if ":" in mac_candidate and len(mac_candidate) == 17:
                hostname = parts[0] if parts[0] != "?" else None
                results.append(ScanResult(ip=ip, mac=mac_candidate, hostname=hostname))
    except Exception as exc:
        logger.error("ARP cache fallback failed: %s", exc)
    logger.debug("ARP cache fallback found %d device(s)", len(results))
    return results
