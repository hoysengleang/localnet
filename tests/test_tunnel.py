"""Tests for Cloudflare tunnel bootstrap behavior."""

import os
import stat
from pathlib import Path

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
