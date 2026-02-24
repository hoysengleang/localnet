<div align="center">

# localnet-control

**Instantly share local dev services with anyone on your network.**

No tunneling. No cloud. No configuration. Just one command.

[![PyPI](https://img.shields.io/pypi/v/localnet-control?color=blue)](https://pypi.org/project/localnet-control/)
[![Python](https://img.shields.io/badge/python-3.9%2B-blue?logo=python&logoColor=white)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/platform-Linux-green)](https://www.kernel.org/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

</div>

---

> **Platform:** This version targets **Linux** first. macOS may work. Windows is not yet supported.

---

## What is it?

`localnet-control` creates a lightweight **TCP proxy** that exposes your local dev service to every device on your LAN — no internet required.

```
Your app (localhost:3000)
        ↓
  localnet proxy  →  http://192.168.1.42:3000
        ↓
  Anyone on your Wi-Fi can open it instantly
```

---

## Install

```bash
pip install localnet-control
```

Or install from source (for development):

```bash
git clone https://github.com/hoysengleang/localnet.git
cd localnet
pip install -e .
```

---

## Quick Start

```bash
# 1. Start your app (e.g. React, FastAPI, etc.)
npm run dev        # running on localhost:3000

# 2. Share it on your network
localnet share 3000

# → Prints: http://192.168.1.42:3000
# → Shows a QR code for mobile devices
```

---

## Commands

### `share` — Expose a local port

```bash
localnet share 3000                        # share port 3000
localnet share localhost:8080              # share a specific host:port
localnet share 3000 --name my-api          # give it a friendly name
localnet share 3000 --port 9000            # listen on a different port
localnet share 3000 --no-qr                # skip the QR code
localnet share 3000 --http-log             # show live HTTP request log (method, path, status, latency)
localnet share 3000 --token myteam123      # require token for access (see Token Auth below)
```

**Access control:**

```bash
localnet share 3000 --allow 192.168.1.10           # allow only this IP
localnet share 3000 --allow 10.0.0.0/24            # allow a subnet
localnet share 3000 --deny 192.168.1.50            # block a specific IP
localnet share 3000 --allow 192.168.1.0/24 --deny 192.168.1.99   # combine rules
```

### Token auth — How clients provide the token

When you share with `--token SECRET`, clients must send the token in one of these ways:

**1. URL query parameter (browsers, simple clients):**
```
http://192.168.1.42:8100/?token=myteam123
```

**2. Authorization header (API clients, curl, fetch, axios):**
```bash
curl -H "Authorization: Bearer myteam123" http://192.168.1.42:8100/
```

Share the full URL with `?token=...` for easy access, or tell your team to add the header for API calls.

---

### `list` — Show active shares

```bash
localnet list
```

---

### `stop` — Stop a share

```bash
localnet stop 3000       # stop by port number
localnet stop my-api     # stop by name
```

---

### `scan` — Discover other shares on your network

```bash
localnet scan
```

Finds other localnet-control instances running on your LAN. Great for teams.

---

### `info` — Show network info

```bash
localnet info
```

Displays your hostname, primary LAN IP, and all network interfaces.

---

## How it works

1. **Detects your LAN IP** automatically using a UDP socket trick (no traffic sent)
2. **Binds to `0.0.0.0`** on the chosen port so all network interfaces are reachable
3. **Proxies TCP traffic** bidirectionally between LAN clients and your local service
4. **Prints a shareable URL** and QR code so anyone can connect instantly
5. **Saves state** to `~/.localnet-control/services.json` to track active shares
6. **Broadcasts presence** via UDP so `localnet scan` can discover other instances

---

## Options Reference

| Flag | Description |
|------|-------------|
| `-p`, `--port` | Custom port to listen on (default: same as target) |
| `-n`, `--name` | Friendly name for this share |
| `--expose` | Use the exact same port as the target |
| `--no-qr` | Disable QR code output |
| `--http-log` | Live HTTP request log (method, path, status, latency) |
| `--token SECRET` | Require token; clients use `?token=SECRET` or `Authorization: Bearer SECRET` |
| `--allow IP/CIDR` | Whitelist an IP or subnet (repeatable) |
| `--deny IP/CIDR` | Blacklist an IP or subnet (repeatable) |

---

## Requirements

| Dependency | Purpose |
|------------|---------|
| Python 3.9+ | Runtime |
| Linux | Primary target platform |
| `rich` | Terminal UI (tables, panels, colors) |
| `qrcode` | QR code generation |

---

## Publish to PyPI (for maintainers)

1. **Create a PyPI account:** https://pypi.org/account/register/
2. **Set up Trusted Publishing:** PyPI → Account Settings → Publishing → Add pending publisher:
   - PyPI project: `localnet-control`
   - Owner: `hoysengleang`, Repo: `localnet`
   - Workflow: `release.yml`
3. **Bump version** in `pyproject.toml` and `src/localnet_access/__init__.py`
4. **Push a tag:**
   ```bash
   git tag v0.1.0
   git push origin v0.1.0
   ```
5. The GitHub Action will build and publish to PyPI.

---

## Project Structure

```
src/localnet_access/
├── cli.py        # Commands and argument parsing
├── proxy.py      # Async TCP proxy engine
├── network.py    # LAN IP detection and port utilities
├── display.py    # Terminal UI with rich
├── acl.py        # IP/CIDR access control rules
├── scanner.py    # LAN discovery (broadcast + scan)
└── Policy/       # Policy enums (discovery port, magic, etc.)
```

---

<div align="center">

MIT License · Built for local development workflows on Linux

</div>
