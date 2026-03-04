from __future__ import annotations

import asyncio
import os
import platform
import re
import shutil
import stat
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from urllib.error import URLError
from urllib.request import urlopen

_TRY_CLOUDFLARE_URL_RE = re.compile(r"https://[a-zA-Z0-9.-]+\.trycloudflare\.com")
_CLOUDFLARED_RELEASE_BASE = "https://github.com/cloudflare/cloudflared/releases/latest/download"
_MANAGED_BIN_DIR = Path.home() / ".localnet-control" / "bin"
_DOWNLOAD_TIMEOUT_SECS = 30


class TunnelError(RuntimeError):
    """Raised when tunnel setup fails."""


@dataclass
class TunnelHandle:
    provider: str
    public_url: str
    process: asyncio.subprocess.Process
    _tasks: list[asyncio.Task[None]] = field(default_factory=list, repr=False)

    async def stop(self) -> None:
        if self.process.returncode is None:
            self.process.terminate()
            try:
                await asyncio.wait_for(self.process.wait(), timeout=5)
            except asyncio.TimeoutError:
                self.process.kill()
                await self.process.wait()

        for task in self._tasks:
            task.cancel()
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)


@dataclass(frozen=True)
class _CloudflaredAsset:
    url: str
    is_archive: bool = False


def _resolve_cloudflared_asset(system_name: str, machine: str) -> _CloudflaredAsset:
    system = system_name.lower()
    arch = machine.lower()

    if system == "linux":
        linux_assets = {
            "x86_64": "cloudflared-linux-amd64",
            "amd64": "cloudflared-linux-amd64",
            "aarch64": "cloudflared-linux-arm64",
            "arm64": "cloudflared-linux-arm64",
            "armv7l": "cloudflared-linux-arm",
            "armv6l": "cloudflared-linux-arm",
        }
        asset = linux_assets.get(arch)
        if not asset:
            raise TunnelError(
                f"Unsupported Linux architecture '{machine}' for auto-install. "
                "Install cloudflared manually."
            )
        return _CloudflaredAsset(url=f"{_CLOUDFLARED_RELEASE_BASE}/{asset}")

    if system == "darwin":
        mac_assets = {
            "x86_64": "cloudflared-darwin-amd64.tgz",
            "amd64": "cloudflared-darwin-amd64.tgz",
            "arm64": "cloudflared-darwin-arm64.tgz",
            "aarch64": "cloudflared-darwin-arm64.tgz",
        }
        asset = mac_assets.get(arch)
        if not asset:
            raise TunnelError(
                f"Unsupported macOS architecture '{machine}' for auto-install. "
                "Install cloudflared manually."
            )
        return _CloudflaredAsset(url=f"{_CLOUDFLARED_RELEASE_BASE}/{asset}", is_archive=True)

    raise TunnelError(
        f"Auto-install for OS '{system_name}' is not supported yet. "
        "Install cloudflared manually."
    )


def _extract_tgz_binary(archive_bytes: bytes) -> bytes:
    import io
    import tarfile

    with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:gz") as tar:
        for member in tar.getmembers():
            if not member.isfile():
                continue
            if Path(member.name).name != "cloudflared":
                continue
            extracted = tar.extractfile(member)
            if extracted is None:
                break
            return extracted.read()
    raise TunnelError("Downloaded cloudflared archive did not contain a binary.")


def _download_cloudflared_binary(dest_path: Path) -> None:
    asset = _resolve_cloudflared_asset(platform.system(), platform.machine())
    tmp_path = dest_path.with_name(f"{dest_path.name}.tmp-{os.getpid()}")

    try:
        with urlopen(asset.url, timeout=_DOWNLOAD_TIMEOUT_SECS) as response:
            payload = response.read()
    except URLError as exc:
        raise TunnelError(
            "Failed to download cloudflared automatically. "
            "Check internet access or install cloudflared manually."
        ) from exc

    if asset.is_archive:
        payload = _extract_tgz_binary(payload)

    tmp_path.write_bytes(payload)
    mode = tmp_path.stat().st_mode
    tmp_path.chmod(mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    tmp_path.replace(dest_path)


def _ensure_cloudflared_binary() -> str:
    installed = shutil.which("cloudflared")
    if installed:
        return installed

    _MANAGED_BIN_DIR.mkdir(parents=True, exist_ok=True)
    managed_path = _MANAGED_BIN_DIR / "cloudflared"

    if managed_path.exists() and os.access(managed_path, os.X_OK):
        return str(managed_path)

    _download_cloudflared_binary(managed_path)
    if not os.access(managed_path, os.X_OK):
        raise TunnelError("Downloaded cloudflared is not executable.")
    return str(managed_path)


async def start_cloudflare_tunnel(local_port: int, timeout: float = 20.0) -> TunnelHandle:
    cloudflared = await asyncio.to_thread(_ensure_cloudflared_binary)

    process = await asyncio.create_subprocess_exec(
        cloudflared,
        "tunnel",
        "--url",
        f"http://127.0.0.1:{local_port}",
        "--no-autoupdate",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    loop = asyncio.get_running_loop()
    public_url_future: asyncio.Future[str] = loop.create_future()
    recent_logs: deque[str] = deque(maxlen=8)

    async def _watch(stream: asyncio.StreamReader | None) -> None:
        if stream is None:
            return
        while True:
            line = await stream.readline()
            if not line:
                return
            text = line.decode("utf-8", errors="ignore").strip()
            if not text:
                continue
            recent_logs.append(text)
            match = _TRY_CLOUDFLARE_URL_RE.search(text)
            if match and not public_url_future.done():
                public_url_future.set_result(match.group(0))

    async def _watch_exit() -> None:
        code = await process.wait()
        if not public_url_future.done():
            details = f"cloudflared exited with code {code}."
            if recent_logs:
                details += " Recent logs: " + " | ".join(recent_logs)
            public_url_future.set_exception(TunnelError(details))

    tasks: list[asyncio.Task[None]] = [
        asyncio.create_task(_watch(process.stdout)),
        asyncio.create_task(_watch(process.stderr)),
        asyncio.create_task(_watch_exit()),
    ]

    try:
        public_url = await asyncio.wait_for(public_url_future, timeout=timeout)
    except Exception as exc:
        if process.returncode is None:
            process.terminate()
            try:
                await asyncio.wait_for(process.wait(), timeout=5)
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()

        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)

        if isinstance(exc, asyncio.TimeoutError):
            msg = "Timed out waiting for Cloudflare tunnel URL."
            if recent_logs:
                msg += " Recent logs: " + " | ".join(recent_logs)
            raise TunnelError(msg) from exc
        if isinstance(exc, TunnelError):
            raise
        raise TunnelError("Failed to start Cloudflare tunnel.") from exc

    return TunnelHandle(provider="cloudflare", public_url=public_url, process=process, _tasks=tasks)
