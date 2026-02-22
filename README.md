<div align="center">

# localnet-access

**Instantly share local dev services with anyone on your network.**

No tunneling. No cloud. No configuration. Just one command.

[![Python](https://img.shields.io/badge/python-3.9%2B-blue?logo=python&logoColor=white)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Version](https://img.shields.io/badge/version-0.1.0-orange)](pyproject.toml)

</div>

---

## What is it?

`localnet-access` creates a lightweight **TCP proxy** that exposes your local dev service to every device on your LAN — no internet required.

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
localnet share 3000 --name my-api         # give it a friendly name
localnet share 3000 --port 9000           # listen on a different port
localnet share 3000 --no-qr              # skip the QR code
```

**Access control:**

```bash
localnet share 3000 --allow 192.168.1.10          # allow only this IP
localnet share 3000 --allow 10.0.0.0/24           # allow a subnet
localnet share 3000 --deny 192.168.1.50           # block a specific IP
localnet share 3000 --allow 192.168.1.0/24 --deny 192.168.1.99  # combine rules
```

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
5. **Saves state** to `~/.localnet-access/services.json` to track active shares

---

## Options Reference

| Flag | Description |
|---|---|
| `-p`, `--port` | Custom port to listen on (default: same as target) |
| `-n`, `--name` | Friendly name for this share |
| `--expose` | Use the exact same port as the target |
| `--no-qr` | Disable QR code output |
| `--allow IP/CIDR` | Whitelist an IP or subnet (repeatable) |
| `--deny IP/CIDR` | Blacklist an IP or subnet (repeatable) |

---

## Requirements

| Dependency | Purpose |
|---|---|
| Python 3.9+ | Runtime |
| `rich` | Terminal UI (tables, panels, colors) |
| `qrcode` | QR code generation |

---

## Project Structure

```
src/localnet_access/
├── cli.py        # Commands and argument parsing
├── proxy.py      # Async TCP proxy engine
├── network.py    # LAN IP detection and port utilities
├── display.py    # Terminal UI with rich
└── acl.py        # IP/CIDR access control rules
```

---

<div align="center">

MIT License · Built for local development workflows

</div>
