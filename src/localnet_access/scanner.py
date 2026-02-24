"""LAN discovery: broadcast presence and scan for other localnet-control instances."""

from __future__ import annotations

import asyncio
import json
import socket
from dataclasses import dataclass

from localnet_access.Policy.ScannerPolicyEnum import ScannerPolicyEnum as ScannerPolicy


@dataclass
class RemoteShare:
    ip: str
    name: str
    share_url: str
    listen_port: int


def _build_beacon(shares: list[dict]) -> bytes:
    """Build a UDP beacon payload announcing our active shares."""
    payload = json.dumps({"magic": ScannerPolicy.DISCOVERY_MAGIC.value, "shares": shares})
    return payload.encode()


def _parse_beacon(data: bytes, sender_ip: str) -> list[RemoteShare] | None:
    """Parse a received beacon. Returns None if it's not a valid beacon."""
    try:
        obj = json.loads(data.decode())
        if obj.get("magic") != ScannerPolicy.DISCOVERY_MAGIC.value:
            return None
        result = []
        for s in obj.get("shares", []):
            result.append(RemoteShare(
                ip=sender_ip,
                name=s.get("name", "unknown"),
                share_url=s.get("share_url", ""),
                listen_port=int(s.get("listen_port", 0)),
            ))
        return result
    except Exception:
        return None


async def broadcast_presence(shares: list[dict], interval: float = 5.0) -> None:
    """Continuously broadcast our shares via UDP until cancelled.
    Called as a background task while the proxy is running.
    """
    beacon = _build_beacon(shares)
    loop = asyncio.get_running_loop()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.setblocking(False)

    try:
        while True:
            try:
                await loop.sock_sendto(sock, beacon, (ScannerPolicy.BROADCAST_ADDR.value, ScannerPolicy.DISCOVERY_PORT.value))
            except OSError:
                pass
            await asyncio.sleep(interval)
    except asyncio.CancelledError:
        pass
    finally:
        sock.close()


def scan_lan(timeout: float = ScannerPolicy.SCAN_TIMEOUT.value) -> list[RemoteShare]:
    """Send a discovery probe and collect replies from other instances.

    This is a synchronous function — it blocks for `timeout` seconds.
    Returns a list of RemoteShare objects discovered on the LAN.
    """
    probe = _build_beacon([])

    recv_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    recv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    recv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    recv_sock.settimeout(timeout)

    send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    send_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    found: list[RemoteShare] = []
    seen_ips: set[str] = set()

    try:
        recv_sock.bind(("", ScannerPolicy.DISCOVERY_PORT.value))
        send_sock.sendto(probe, (ScannerPolicy.BROADCAST_ADDR.value, ScannerPolicy.DISCOVERY_PORT.value))

        deadline = _monotonic() + timeout
        while True:
            remaining = deadline - _monotonic()
            if remaining <= 0:
                break
            recv_sock.settimeout(remaining)
            try:
                data, addr = recv_sock.recvfrom(4096)
                sender_ip = addr[0]

                if sender_ip in _get_local_ips():
                    continue
                if sender_ip in seen_ips:
                    continue

                shares = _parse_beacon(data, sender_ip)
                if shares is not None:
                    seen_ips.add(sender_ip)
                    found.extend(shares)
            except TimeoutError:
                break
            except OSError:
                break
    except OSError:
        pass
    finally:
        recv_sock.close()
        send_sock.close()

    return found


def _monotonic() -> float:
    import time
    return time.monotonic()


def _get_local_ips() -> set[str]:
    """Return all local IP addresses to filter out self-replies."""
    ips: set[str] = {"127.0.0.1"}
    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None, socket.AF_INET):
            ips.add(info[4][0])
    except OSError:
        pass
    return ips
