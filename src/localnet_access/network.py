from __future__ import annotations

import socket
import subprocess
from dataclasses import dataclass


@dataclass
class NetworkInfo:
      hostname   : str
      local_ip   : str
      interfaces : list[dict[str, str]]


def get_local_ip() -> str:
    """Get the primary LAN IP by opening a UDP socket (no traffic sent)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("10.255.255.255", 1))
            return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"


def get_all_interfaces() -> list[dict[str, str]]:
    """Return all network interfaces with their IPv4 addresses."""
    interfaces: list[dict[str, str]] = []
    try:
        result = subprocess.run(
            ["ip", "-4", "-o", "addr", "show"],
            capture_output=True, text=True, timeout=5,
        )
        for line in result.stdout.strip().splitlines():
            parts = line.split()
            if len(parts) >= 4:
                name = parts[1]
                addr = parts[3].split("/")[0]
                interfaces.append({"name": name, "ip": addr})
    except (FileNotFoundError, subprocess.TimeoutExpired):
        ip = get_local_ip()
        if ip != "127.0.0.1":
            interfaces.append({"name": "unknown", "ip": ip})
        interfaces.append({"name": "lo", "ip": "127.0.0.1"})
    return interfaces


def get_network_info() -> NetworkInfo:
    hostname = socket.gethostname()
    local_ip = get_local_ip()
    interfaces = get_all_interfaces()
    return NetworkInfo(hostname=hostname, local_ip=local_ip, interfaces=interfaces)


def is_port_in_use(port: int, host: str = "127.0.0.1") -> bool:
    """Check if a port already has something listening on it."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(1)
        return s.connect_ex((host, port)) == 0


def find_free_port(start: int = 8100, end: int = 8200) -> int | None:
    """Find an available port in the given range."""
    for port in range(start, end):
        if not is_port_in_use(port, "0.0.0.0"):
            return port
    return None


def parse_target(target: str) -> tuple[str, int]:
    """Parse a target string like '3000', 'localhost:3000', '127.0.0.1:8080'."""
    if ":" in target:
        host, port_str = target.rsplit(":", 1)
        return host, int(port_str)
    return "127.0.0.1", int(target)
