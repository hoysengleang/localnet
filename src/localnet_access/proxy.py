from __future__ import annotations

import asyncio
import signal
import os
import json
from dataclasses import dataclass, asdict, field
from pathlib import Path
from datetime import datetime
from typing import Callable

from localnet_access.acl import AccessControl

SHARE_STATE_DIR = Path.home() / ".localnet-access"


@dataclass
class SharedService:
    name: str
    target_host: str
    target_port: int
    listen_port: int
    local_ip: str
    pid: int
    started_at: str
    share_url: str
    allow_rules: list[str] = field(default_factory=list)
    deny_rules: list[str] = field(default_factory=list)


def _state_file() -> Path:
    SHARE_STATE_DIR.mkdir(parents=True, exist_ok=True)
    return SHARE_STATE_DIR / "services.json"


def save_service(service: SharedService) -> None:
    path = _state_file()
    services = load_services()
    services = [s for s in services if s.listen_port != service.listen_port]
    services.append(service)
    path.write_text(json.dumps([asdict(s) for s in services], indent=2))


def remove_service(listen_port: int) -> bool:
    path = _state_file()
    services = load_services()
    filtered = [s for s in services if s.listen_port != listen_port]
    if len(filtered) == len(services):
        return False
    path.write_text(json.dumps([asdict(s) for s in filtered], indent=2))
    return True


def load_services() -> list[SharedService]:
    path = _state_file()
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text())
        return [SharedService(**item) for item in data]
    except (json.JSONDecodeError, TypeError):
        return []


def cleanup_dead_services() -> list[SharedService]:
    """Remove entries whose PID is no longer running."""
    services = load_services()
    alive = []
    for svc in services:
        try:
            os.kill(svc.pid, 0)
            alive.append(svc)
        except OSError:
            pass
    path = _state_file()
    path.write_text(json.dumps([asdict(s) for s in alive], indent=2))
    return alive


async def _pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        while True:
            data = await reader.read(65536)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except (ConnectionResetError, BrokenPipeError, asyncio.CancelledError):
        pass
    finally:
        writer.close()


async def _handle_client(
    client_reader: asyncio.StreamReader,
    client_writer: asyncio.StreamWriter,
    target_host: str,
    target_port: int,
) -> None:
    try:
        upstream_reader, upstream_writer = await asyncio.wait_for(
            asyncio.open_connection(target_host, target_port),
            timeout=5,
        )
    except (OSError, asyncio.TimeoutError):
        client_writer.close()
        return

    await asyncio.gather(
        _pipe(client_reader, upstream_writer),
        _pipe(upstream_reader, client_writer),
    )


async def run_proxy(
    target_host: str,
    target_port: int,
    listen_port: int,
    acl: AccessControl | None = None,
    on_connection: Callable[[str, bool], None] | None = None,
    on_ready: asyncio.Future | None = None,
) -> None:
    """Start the proxy and run until cancelled.

    Args:
        acl: Access control rules. None means allow all.
        on_connection: Optional callback(ip, allowed) for live logging.
    """
    acl = acl or AccessControl()

    async def handler(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        peer = w.get_extra_info("peername")
        client_ip = peer[0] if peer else "unknown"

        if not acl.is_allowed(client_ip):
            if on_connection:
                on_connection(client_ip, False)
            w.close()
            return

        if on_connection:
            on_connection(client_ip, True)

        await _handle_client(r, w, target_host, target_port)

    server = await asyncio.start_server(handler, "0.0.0.0", listen_port)
    if on_ready:
        on_ready.set_result(True)

    loop = asyncio.get_running_loop()
    stop = loop.create_future()

    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, lambda: stop.done() or stop.set_result(True))

    try:
        await stop
    finally:
        server.close()
        await server.wait_closed()
