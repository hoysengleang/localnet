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

SHARE_STATE_DIR = Path.home() / ".localnet-control"

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
    path     = _state_file()
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


def _get_content_length(raw: bytes) -> int | None:
    """Extract Content-Length from headers. Returns None if absent."""
    val = _get_header(raw, "Content-Length")
    if val is None:
        return None
    try:
        return int(val)
    except ValueError:
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

    auth = _get_header(raw_request, "Authorization")
    if auth and auth == f"Bearer {token}":
        return True

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
        b"WWW-Authenticate: Bearer realm=\"localnet-control\"\r\n"
        b"Connection: close\r\n"
        b"Content-Length: " + str(len(body)).encode() + b"\r\n"
        b"\r\n" + body
    )


# ---------------------------------------------------------------------------
# HTTP request/response reading
# ---------------------------------------------------------------------------


async def _read_one_http_request(reader: asyncio.StreamReader, buf: bytearray) -> bytes | None:
    """Read one complete HTTP request from reader, using buf as scratch.
    Returns the full request bytes, or None if connection closed / not HTTP.
    """
    while True:
        chunk = await reader.read(8192)
        if not chunk:
            return None
        buf.extend(chunk)

        # Need at least request line + \r\n\r\n
        header_end = buf.find(b"\r\n\r\n")
        if header_end == -1:
            if len(buf) > 65536:
                return None
            continue

        header_block = bytes(buf[: header_end + 4])
        parsed = _parse_request_line(header_block)
        if not parsed:
            return None

        body_len = _get_content_length(header_block)
        total = header_end + 4 + (body_len or 0)
        while len(buf) < total:
            extra = await reader.read(total - len(buf))
            if not extra:
                break
            buf.extend(extra)

        request = bytes(buf[:total])
        del buf[:total]
        return request


async def _read_one_http_response(reader: asyncio.StreamReader, buf: bytearray) -> tuple[bytes, int, float] | None:
    """Read one complete HTTP response. Returns (full_response_bytes, status_code, duration_ms) or None."""
    t_start = time.monotonic()
    while True:
        chunk = await reader.read(65536)
        if chunk:
            buf.extend(chunk)
        elif not buf:
            return None

        header_end = buf.find(b"\r\n\r\n")
        if header_end == -1:
            if len(buf) > 65536:
                return None
            continue

        header_block = bytes(buf[: header_end + 4])
        status = _parse_status_line(header_block) or 0
        body_len = _get_content_length(header_block)
        total = header_end + 4 + (body_len if body_len is not None else 0)
        while len(buf) < total:
            extra = await reader.read(total - len(buf))
            if not extra:
                total = len(buf)
                break
            buf.extend(extra)

        response = bytes(buf[:total])
        del buf[:total]
        duration = (time.monotonic() - t_start) * 1000
        return (response, status, duration)


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
    """Handle a connection with HTTP parsing, token check, and per-request logging.
    Supports keep-alive: logs every request/response pair on the connection.
    """
    client_ip = "unknown"
    peer = client_writer.get_extra_info("peername")
    if peer:
        client_ip = peer[0]

    client_buf: bytearray = bytearray()

    while True:
        request = await _read_one_http_request(client_reader, client_buf)
        if not request:
            break

        parsed = _parse_request_line(request)
        if not parsed:
            if on_http:
                on_http(HttpEntry(client_ip, "???", "(non-HTTP, e.g. HTTPS)", 0, 0.0))
            # Non-HTTP — pipe remainder of connection and exit
            client_writer.write(request)
            await client_writer.drain()
            while True:
                chunk = await client_reader.read(65536)
                if not chunk:
                    break
                client_writer.write(chunk)
                await client_writer.drain()
            break

        method, path = parsed

        if token and not _check_token(request, token):
            client_writer.write(_build_401_response())
            await client_writer.drain()
            if on_http:
                on_http(HttpEntry(client_ip, method, path, 401, 0.0))
            continue

        try:
            upstream_reader, upstream_writer = await asyncio.wait_for(
                asyncio.open_connection(target_host, target_port),
                timeout=5,
            )
        except (OSError, asyncio.TimeoutError):
            break

        try:
            upstream_writer.write(request)
            await upstream_writer.drain()

            upstream_buf: bytearray = bytearray()
            result = await _read_one_http_response(upstream_reader, upstream_buf)
            if result is None:
                break
            response, status, duration = result

            if on_http:
                on_http(HttpEntry(client_ip, method, path, status, duration))

            client_writer.write(response)
            await client_writer.drain()

            upstream_writer.close()
        except (ConnectionResetError, BrokenPipeError, asyncio.CancelledError):
            pass

    try:
        client_writer.close()
    except OSError:
        pass


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
