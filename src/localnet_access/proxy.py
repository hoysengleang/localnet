from __future__ import annotations

import asyncio
import json
import os
import signal
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Callable
from urllib.parse import parse_qs, urlparse

from localnet_access.acl import AccessControl

SHARE_STATE_DIR = Path.home() / ".localnet-access"

_NOT_HTTP = object()


@dataclass
class HttpEntry:
    """One parsed HTTP request + its upstream response summary."""
    client_ip: str
    method: str
    path: str
    status: int
    duration_ms: float


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
    token: str = ""
    http_log: bool = False


# ---------------------------------------------------------------------------
# State persistence
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Low-level pipe
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# HTTP parsing helpers
# ---------------------------------------------------------------------------

def _parse_request_line(first_bytes: bytes) -> tuple[str, str] | None:
    """Extract (METHOD, path) from the first bytes of an HTTP request.
    Returns None if the data doesn't look like HTTP.
    """
    try:
        first_line = first_bytes.split(b"\r\n", 1)[0].decode("latin-1")
        parts = first_line.split(" ", 2)
        if len(parts) == 3 and parts[2].startswith("HTTP/"):
            return parts[0], parts[1]
    except Exception:
        pass
    return None


def _parse_status_line(first_bytes: bytes) -> int | None:
    """Extract the HTTP status code from the first bytes of a response."""
    try:
        first_line = first_bytes.split(b"\r\n", 1)[0].decode("latin-1")
        parts = first_line.split(" ", 2)
        if len(parts) >= 2 and parts[0].startswith("HTTP/"):
            return int(parts[1])
    except Exception:
        pass
    return None


def _get_header(raw: bytes, name: str) -> str | None:
    """Extract a header value from raw HTTP bytes (case-insensitive)."""
    try:
        header_block = raw.split(b"\r\n\r\n", 1)[0].decode("latin-1")
        needle = name.lower() + ":"
        for line in header_block.splitlines()[1:]:
            if line.lower().startswith(needle):
                return line.split(":", 1)[1].strip()
    except Exception:
        pass
    return None


def _check_token(raw_request: bytes, token: str) -> bool:
    """Return True if the request carries the correct token.

    Checks two places:
      1. Authorization: Bearer <token>
      2. ?token=<token> query parameter in the request path
    """
    if not token:
        return True

    # Check Authorization header
    auth = _get_header(raw_request, "Authorization")
    if auth and auth == f"Bearer {token}":
        return True

    # Check query string
    try:
        first_line = raw_request.split(b"\r\n", 1)[0].decode("latin-1")
        raw_path = first_line.split(" ", 2)[1]
        parsed = urlparse(raw_path)
        params = parse_qs(parsed.query)
        if params.get("token", [None])[0] == token:
            return True
    except Exception:
        pass

    return False


def _build_401_response() -> bytes:
    body = b'{"error": "Unauthorized. Provide a valid token."}'
    return (
        b"HTTP/1.1 401 Unauthorized\r\n"
        b"Content-Type: application/json\r\n"
        b"WWW-Authenticate: Bearer realm=\"localnet-access\"\r\n"
        b"Connection: close\r\n"
        b"Content-Length: " + str(len(body)).encode() + b"\r\n"
        b"\r\n" + body
    )


# ---------------------------------------------------------------------------
# HTTP-aware client handler
# ---------------------------------------------------------------------------

async def _handle_http_client(
    client_reader: asyncio.StreamReader,
    client_writer: asyncio.StreamWriter,
    target_host: str,
    target_port: int,
    token: str,
    on_http: Callable[[HttpEntry], None] | None,
) -> None:
    """Handle a connection with HTTP parsing, token check, and request logging."""
    # Peek at the first chunk — enough to read the request line + headers
    try:
        first_chunk = await asyncio.wait_for(client_reader.read(8192), timeout=5)
    except asyncio.TimeoutError:
        client_writer.close()
        return

    if not first_chunk:
        client_writer.close()
        return

    parsed = _parse_request_line(first_chunk)

    # Token check — only for HTTP traffic
    if token and parsed:
        if not _check_token(first_chunk, token):
            client_writer.write(_build_401_response())
            await client_writer.drain()
            client_writer.close()
            # Log the rejected request
            if on_http:
                client_ip = client_writer.get_extra_info("peername")
                ip = client_ip[0] if client_ip else "unknown"
                method, path = parsed
                on_http(HttpEntry(ip, method, path, 401, 0.0))
            return

    # Connect upstream
    try:
        upstream_reader, upstream_writer = await asyncio.wait_for(
            asyncio.open_connection(target_host, target_port),
            timeout=5,
        )
    except (OSError, asyncio.TimeoutError):
        client_writer.close()
        return

    # Forward the already-read first chunk upstream
    upstream_writer.write(first_chunk)
    await upstream_writer.drain()

    if parsed and on_http:
        # Read the first chunk of the response to get the status code
        t_start = time.monotonic()
        method, path = parsed
        client_ip = client_writer.get_extra_info("peername")
        ip = client_ip[0] if client_ip else "unknown"

        async def _log_response_and_pipe() -> None:
            logged = False
            try:
                while True:
                    data = await upstream_reader.read(65536)
                    if not data:
                        break
                    if not logged:
                        status = _parse_status_line(data) or 0
                        duration = (time.monotonic() - t_start) * 1000
                        on_http(HttpEntry(ip, method, path, status, duration))
                        logged = True
                    client_writer.write(data)
                    await client_writer.drain()
            except (ConnectionResetError, BrokenPipeError, asyncio.CancelledError):
                pass
            finally:
                client_writer.close()

        await asyncio.gather(
            _log_response_and_pipe(),
            _pipe(client_reader, upstream_writer),
        )
    else:
        # Non-HTTP or no logging — plain bidirectional pipe
        await asyncio.gather(
            _pipe(client_reader, upstream_writer),
            _pipe(upstream_reader, client_writer),
        )


async def _handle_plain_client(
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


# ---------------------------------------------------------------------------
# Public proxy entry point
# ---------------------------------------------------------------------------

async def run_proxy(
    target_host: str,
    target_port: int,
    listen_port: int,
    acl: AccessControl | None = None,
    token: str = "",
    http_log: bool = False,
    on_connection: Callable[[str, bool], None] | None = None,
    on_http: Callable[[HttpEntry], None] | None = None,
    on_ready: asyncio.Future | None = None,
) -> None:
    """Start the proxy and run until SIGINT/SIGTERM.

    Args:
        acl:           IP access control rules.
        token:         If set, require this token on every HTTP request.
        http_log:      If True, parse HTTP and call on_http per request.
        on_connection: Callback(ip, allowed) for connection-level logging.
        on_http:       Callback(HttpEntry) for HTTP request logging.
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

        if http_log or token:
            await _handle_http_client(r, w, target_host, target_port, token, on_http)
        else:
            await _handle_plain_client(r, w, target_host, target_port)

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
