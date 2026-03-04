from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import os
import secrets
import signal
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Callable
from urllib.parse import parse_qsl, quote, urlencode, urlparse, urlunparse

from localnet_access.acl import AccessControl

SHARE_STATE_DIR = Path.home() / ".localnet-control"
_TOKEN_COOKIE_NAME = "localnet_token"
_COOKIE_SIGNING_SECRET = secrets.token_urlsafe(32)

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


def _is_chunked_transfer(raw: bytes) -> bool:
    """Return True if Transfer-Encoding includes chunked."""
    val = _get_header(raw, "Transfer-Encoding")
    if val is None:
        return False
    return any(part.strip().lower() == "chunked" for part in val.split(","))


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

    has_query_token, query_token = _extract_query_token(raw_request)
    if has_query_token:
        return query_token == token

    auth = _get_header(raw_request, "Authorization")
    if auth and auth == f"Bearer {token}":
        return True

    if _has_token_cookie(raw_request, token):
        return True

    return False


def _request_has_query_token(raw_request: bytes, token: str) -> bool:
    """Return True when the request query string carries the expected token."""
    has_query_token, query_token = _extract_query_token(raw_request)
    return has_query_token and query_token == token


def _extract_query_token(raw_request: bytes) -> tuple[bool, str | None]:
    """Extract token query param. Returns (present, value)."""
    try:
        first_line = raw_request.split(b"\r\n", 1)[0].decode("latin-1")
        raw_path = first_line.split(" ", 2)[1]
        parsed = urlparse(raw_path)
        for key, value in parse_qsl(parsed.query, keep_blank_values=True):
            if key == "token":
                return True, value
    except Exception:
        return False, None
    return False, None


def _has_token_cookie(raw_request: bytes, token: str) -> bool:
    """Return True when Cookie header carries the expected localnet token."""
    cookie_header = _get_header(raw_request, "Cookie")
    if not cookie_header:
        return False
    for pair in cookie_header.split(";"):
        if "=" not in pair:
            continue
        key, value = pair.split("=", 1)
        if key.strip() == _TOKEN_COOKIE_NAME and _is_valid_signed_cookie(value.strip(), token):
            return True
    return False


def _build_401_response() -> bytes:
    body = b'{"error": "Unauthorized. Provide a valid token."}'
    return (
        b"HTTP/1.1 401 Unauthorized\r\n"
        + b"Content-Type: application/json\r\n"
        + b"WWW-Authenticate: Bearer realm=\"localnet-control\"\r\n"
        + f"Set-Cookie: {_TOKEN_COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0\r\n".encode("latin-1")
        + b"Connection: close\r\n"
        + b"Content-Length: " + str(len(body)).encode() + b"\r\n"
        + b"\r\n" + body
    )


def _remove_token_from_path(path: str) -> str:
    """Strip token from URL path query while keeping other query params."""
    try:
        parsed = urlparse(path)
        filtered = [(k, v) for (k, v) in parse_qsl(parsed.query, keep_blank_values=True) if k != "token"]
        clean_query = urlencode(filtered, doseq=True)
        rebuilt = parsed._replace(query=clean_query)
        return urlunparse(rebuilt) or "/"
    except Exception:
        return "/"


def _build_token_cookie_redirect_response(location: str, token: str) -> bytes:
    """Return a redirect response that sets auth cookie for browser follow-up requests."""
    cookie_value = quote(_build_signed_cookie(token), safe="")
    body = b'{"ok": true, "message": "Token accepted. Redirecting."}'
    return (
        b"HTTP/1.1 307 Temporary Redirect\r\n"
        b"Content-Type: application/json\r\n"
        + f"Location: {location}\r\n".encode("latin-1")
        + f"Set-Cookie: {_TOKEN_COOKIE_NAME}={cookie_value}; Path=/; HttpOnly; SameSite=Lax\r\n".encode("latin-1")
        + b"Cache-Control: no-store\r\n"
        + b"Connection: close\r\n"
        + b"Content-Length: " + str(len(body)).encode() + b"\r\n"
        + b"\r\n" + body
    )


def _cookie_sig(token: str) -> str:
    return hmac.new(
        _COOKIE_SIGNING_SECRET.encode("utf-8"),
        token.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def _build_signed_cookie(token: str) -> str:
    return f"v1.{_cookie_sig(token)}"


def _is_valid_signed_cookie(cookie_value: str, token: str) -> bool:
    expected = _build_signed_cookie(token)
    return hmac.compare_digest(cookie_value, expected)


# ---------------------------------------------------------------------------
# HTTP request/response reading
# ---------------------------------------------------------------------------


async def _read_chunked_until_end(
    reader: asyncio.StreamReader,
    buf: bytearray,
    body_start: int,
) -> int | None:
    """Return end offset of a chunked body (including trailers), or None on parse failure."""
    pos = body_start
    while True:
        line_end = buf.find(b"\r\n", pos)
        while line_end == -1:
            extra = await reader.read(8192)
            if not extra:
                return None
            buf.extend(extra)
            line_end = buf.find(b"\r\n", pos)

        size_line = bytes(buf[pos:line_end]).split(b";", 1)[0].strip()
        try:
            chunk_size = int(size_line, 16)
        except ValueError:
            return None

        pos = line_end + 2
        if chunk_size == 0:
            while True:
                if len(buf) >= pos + 2 and buf[pos:pos + 2] == b"\r\n":
                    return pos + 2

                trailer_end = buf.find(b"\r\n\r\n", pos)
                if trailer_end != -1:
                    return trailer_end + 4

                extra = await reader.read(8192)
                if not extra:
                    return None
                buf.extend(extra)

        need = pos + chunk_size + 2
        while len(buf) < need:
            extra = await reader.read(need - len(buf))
            if not extra:
                return None
            buf.extend(extra)
        if buf[pos + chunk_size:need] != b"\r\n":
            return None
        pos = need


def _response_has_no_body(status: int) -> bool:
    """Return True for status codes that must not carry a body."""
    return (100 <= status < 200) or status in (204, 304)


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

        body_start = header_end + 4
        if _is_chunked_transfer(header_block):
            total = await _read_chunked_until_end(reader, buf, body_start)
            if total is None:
                return None
        else:
            body_len = _get_content_length(header_block)
            total = body_start + (body_len or 0)
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
        body_start = header_end + 4
        if _response_has_no_body(status):
            total = body_start
        elif _is_chunked_transfer(header_block):
            total = await _read_chunked_until_end(reader, buf, body_start)
            if total is None:
                return None
        else:
            body_len = _get_content_length(header_block)
            if body_len is not None:
                total = body_start + body_len
                while len(buf) < total:
                    extra = await reader.read(total - len(buf))
                    if not extra:
                        total = len(buf)
                        break
                    buf.extend(extra)
            else:
                # Fallback for connection-close framed responses.
                while True:
                    extra = await reader.read(65536)
                    if not extra:
                        break
                    buf.extend(extra)
                total = len(buf)

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
            break

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


async def _handle_token_client(
    client_reader: asyncio.StreamReader,
    client_writer: asyncio.StreamWriter,
    target_host: str,
    target_port: int,
    token: str,
    on_http: Callable[[HttpEntry], None] | None,
) -> None:
    """Token gate for HTTP, then switch to transparent TCP piping.

    This is more robust for tunnel/proxy paths that use keep-alive, upgrades,
    or streaming after the initial authenticated request.
    """
    client_ip = "unknown"
    peer = client_writer.get_extra_info("peername")
    if peer:
        client_ip = peer[0]

    client_buf: bytearray = bytearray()
    request = await _read_one_http_request(client_reader, client_buf)
    if not request:
        try:
            client_writer.close()
        except OSError:
            pass
        return

    parsed = _parse_request_line(request)
    if not parsed:
        try:
            client_writer.close()
        except OSError:
            pass
        return

    method, path = parsed
    should_set_token_cookie = _request_has_query_token(request, token)
    has_token_cookie = _has_token_cookie(request, token)

    if token and not _check_token(request, token):
        client_writer.write(_build_401_response())
        await client_writer.drain()
        if on_http:
            on_http(HttpEntry(client_ip, method, path, 401, 0.0))
        try:
            client_writer.close()
        except OSError:
            pass
        return

    if should_set_token_cookie and not has_token_cookie:
        redirect_target = _remove_token_from_path(path)
        client_writer.write(_build_token_cookie_redirect_response(redirect_target, token))
        await client_writer.drain()
        if on_http:
            on_http(HttpEntry(client_ip, method, path, 307, 0.0))
        try:
            client_writer.close()
        except OSError:
            pass
        return

    try:
        upstream_reader, upstream_writer = await asyncio.wait_for(
            asyncio.open_connection(target_host, target_port),
            timeout=5,
        )
    except (OSError, asyncio.TimeoutError):
        try:
            client_writer.close()
        except OSError:
            pass
        return

    try:
        upstream_writer.write(request)
        if client_buf:
            upstream_writer.write(bytes(client_buf))
            client_buf.clear()
        await upstream_writer.drain()

        if on_http:
            on_http(HttpEntry(client_ip, method, path, 0, 0.0))

        await asyncio.gather(
            _pipe(client_reader, upstream_writer),
            _pipe(upstream_reader, client_writer),
        )
    except (ConnectionResetError, BrokenPipeError, asyncio.CancelledError):
        try:
            upstream_writer.close()
        except OSError:
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
        token:         If set, require this token on HTTP entry. After first auth,
                       traffic is forwarded as a raw stream.
        http_log:      If True and token is empty, parse HTTP and call on_http per request.
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

        if token:
            await _handle_token_client(r, w, target_host, target_port, token, on_http)
        elif http_log:
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
