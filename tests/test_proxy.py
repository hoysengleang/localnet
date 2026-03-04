"""Tests for HTTP parsing and token behavior in proxy mode."""

import asyncio

import localnet_access.proxy as proxy


class _DummyWriter:
    def __init__(self) -> None:
        self.buffer = bytearray()
        self.closed = False

    def get_extra_info(self, name: str):
        if name == "peername":
            return ("127.0.0.1", 12345)
        return None

    def write(self, data: bytes) -> None:
        self.buffer.extend(data)

    async def drain(self) -> None:
        return None

    def close(self) -> None:
        self.closed = True


def _reader_from_bytes(payload: bytes) -> asyncio.StreamReader:
    reader = asyncio.StreamReader()
    reader.feed_data(payload)
    reader.feed_eof()
    return reader


def test_read_one_http_request_supports_chunked_body():
    payload = (
        b"POST /upload HTTP/1.1\r\n"
        b"Host: localhost\r\n"
        b"Transfer-Encoding: chunked\r\n"
        b"\r\n"
        b"4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n"
    )

    async def _run() -> bytes | None:
        return await proxy._read_one_http_request(_reader_from_bytes(payload), bytearray())

    request = asyncio.run(_run())
    assert request == payload


def test_read_one_http_response_supports_chunked_body():
    payload = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: text/plain\r\n"
        b"Transfer-Encoding: chunked\r\n"
        b"\r\n"
        b"4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n"
    )

    async def _run() -> tuple[bytes, int, float] | None:
        return await proxy._read_one_http_response(_reader_from_bytes(payload), bytearray())

    result = asyncio.run(_run())
    assert result is not None
    response, status, duration = result
    assert response == payload
    assert status == 200
    assert duration >= 0.0


def test_read_one_http_response_supports_connection_close_body():
    payload = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: text/plain\r\n"
        b"\r\n"
        b"hello"
    )

    async def _run() -> tuple[bytes, int, float] | None:
        return await proxy._read_one_http_response(_reader_from_bytes(payload), bytearray())

    result = asyncio.run(_run())
    assert result is not None
    response, status, _ = result
    assert response == payload
    assert status == 200


def test_unauthorized_token_request_closes_connection():
    async def _run() -> None:
        reader = asyncio.StreamReader()
        reader.feed_data(
            b"GET / HTTP/1.1\r\n"
            b"Host: localhost\r\n"
            b"\r\n"
        )
        writer = _DummyWriter()
        entries: list[proxy.HttpEntry] = []

        await asyncio.wait_for(
            proxy._handle_http_client(
                client_reader=reader,
                client_writer=writer,
                target_host="127.0.0.1",
                target_port=3000,
                token="secret-token",
                on_http=entries.append,
            ),
            timeout=0.2,
        )
        assert writer.closed
        assert b"401 Unauthorized" in bytes(writer.buffer)
        assert len(entries) == 1
        assert entries[0].status == 401

    asyncio.run(_run())


def test_check_token_accepts_cookie():
    signed = proxy._build_signed_cookie("secret-token")
    raw = b"GET / HTTP/1.1\r\n" + b"Host: localhost\r\n" + \
        f"Cookie: session=abc; localnet_token={signed}\r\n".encode("latin-1") + b"\r\n"
    assert proxy._check_token(raw, "secret-token")


def test_check_token_rejects_wrong_query_even_with_valid_cookie():
    signed = proxy._build_signed_cookie("secret-token")
    raw = b"GET /?token=wrong-token HTTP/1.1\r\n" + b"Host: localhost\r\n" + \
        f"Cookie: localnet_token={signed}\r\n".encode("latin-1") + b"\r\n"
    assert proxy._check_token(raw, "secret-token") is False


def test_remove_token_from_path_preserves_other_query_params():
    clean = proxy._remove_token_from_path("/api/items?token=secret-token&page=2&lang=en")
    assert clean == "/api/items?page=2&lang=en"


def test_build_token_cookie_redirect_response_sets_cookie_and_location():
    response = proxy._build_token_cookie_redirect_response("/dashboard", "secret-token")
    assert b"HTTP/1.1 307 Temporary Redirect" in response
    assert b"Location: /dashboard" in response
    assert b"Set-Cookie: localnet_token=v1." in response


def test_signed_cookie_invalid_after_secret_rotation(monkeypatch):
    cookie = proxy._build_signed_cookie("secret-token")
    monkeypatch.setattr(proxy, "_COOKIE_SIGNING_SECRET", "rotated-secret")
    assert proxy._is_valid_signed_cookie(cookie, "secret-token") is False
