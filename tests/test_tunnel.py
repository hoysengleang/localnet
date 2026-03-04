"""Tests for Cloudflare tunnel bootstrap behavior."""

import os
import stat
from pathlib import Path
from urllib.error import HTTPError, URLError

import pytest

import localnet_access.tunnel as tunnel


def test_resolve_linux_amd64_asset():
    asset = tunnel._resolve_cloudflared_asset("Linux", "x86_64")
    assert asset.url.endswith("/cloudflared-linux-amd64")
    assert asset.is_archive is False


def test_resolve_macos_arm64_asset():
    asset = tunnel._resolve_cloudflared_asset("Darwin", "arm64")
    assert asset.url.endswith("/cloudflared-darwin-arm64.tgz")
    assert asset.is_archive is True


def test_resolve_unsupported_os_raises():
    with pytest.raises(tunnel.TunnelError):
        tunnel._resolve_cloudflared_asset("Windows", "x86_64")


def test_ensure_cloudflared_uses_system_binary(monkeypatch):
    monkeypatch.setattr(tunnel.shutil, "which", lambda _: "/usr/bin/cloudflared")
    assert tunnel._ensure_cloudflared_binary() == "/usr/bin/cloudflared"


def test_ensure_cloudflared_downloads_when_missing(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(tunnel.shutil, "which", lambda _: None)
    monkeypatch.setattr(tunnel, "_MANAGED_BIN_DIR", tmp_path)

    def fake_download(dest_path: Path) -> None:
        dest_path.write_text("#!/bin/sh\necho cloudflared\n")
        dest_path.chmod(dest_path.stat().st_mode | stat.S_IXUSR)

    monkeypatch.setattr(tunnel, "_download_cloudflared_binary", fake_download)

    resolved = tunnel._ensure_cloudflared_binary()
    assert resolved == str(tmp_path / "cloudflared")
    assert os.access(resolved, os.X_OK)


def test_is_unready_trycloudflare_response_detects_1033():
    body = b"<html><body>Error 1033 Cloudflare Tunnel error unable to resolve it</body></html>"
    assert tunnel._is_unready_trycloudflare_response(530, body)


def test_is_unready_trycloudflare_response_ignores_other_status():
    body = b"not important"
    assert tunnel._is_unready_trycloudflare_response(404, body) is False


def test_probe_public_url_ready_true_on_normal_response(monkeypatch):
    class _Response:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def read(self, _: int = -1):
            return b"ok"

    monkeypatch.setattr(tunnel, "urlopen", lambda *args, **kwargs: _Response())
    assert tunnel._probe_public_url_ready("https://example.trycloudflare.com")


def test_probe_public_url_ready_false_on_530_1033(monkeypatch):
    class _FakeHTTPError(HTTPError):
        def read(self, amt: int = -1):  # noqa: ARG002
            return b"Error 1033 Cloudflare Tunnel error unable to resolve it"

    def fake_urlopen_with_body(*args, **kwargs):
        raise _FakeHTTPError(
            url="https://example.trycloudflare.com",
            code=530,
            msg="Origin DNS error",
            hdrs=None,
            fp=None,
        )

    monkeypatch.setattr(tunnel, "urlopen", fake_urlopen_with_body)
    assert tunnel._probe_public_url_ready("https://example.trycloudflare.com") is False


def test_probe_public_url_ready_true_on_non_530_http_error(monkeypatch):
    class _FakeHTTPError(HTTPError):
        def read(self, amt: int = -1):  # noqa: ARG002
            return b"unauthorized"

    def fake_urlopen(*args, **kwargs):
        raise _FakeHTTPError(
            url="https://example.trycloudflare.com",
            code=401,
            msg="Unauthorized",
            hdrs=None,
            fp=None,
        )

    monkeypatch.setattr(tunnel, "urlopen", fake_urlopen)
    assert tunnel._probe_public_url_ready("https://example.trycloudflare.com")


def test_probe_public_url_ready_false_on_urlerror(monkeypatch):
    def fake_urlopen(*args, **kwargs):
        raise URLError("network down")

    monkeypatch.setattr(tunnel, "urlopen", fake_urlopen)
    assert tunnel._probe_public_url_ready("https://example.trycloudflare.com") is False
