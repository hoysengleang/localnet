# localnet-access

**Instantly share local dev services with anyone on your network.**

No tunneling, no cloud, no configuration. Just run one command and share the URL.

## Install

```bash
pip install -e .
```

## Usage

### Share a local service

```bash
# Share port 3000 on your network
localnet share 3000

# Share with a custom name
localnet share 3000 --name my-api

# Share on a different port
localnet share 3000 --port 9000

# Skip QR code
localnet share 3000 --no-qr
```

### List active shares

```bash
localnet list
```

### Stop a share

```bash
localnet stop 3000       # by port
localnet stop my-api     # by name
```

### Show network info

```bash
localnet info
```

## How it works

`localnet-access` creates a lightweight TCP proxy that:

1. Detects your LAN IP address automatically
2. Binds to `0.0.0.0` on the specified port
3. Forwards all traffic to your local service
4. Prints a shareable URL and QR code

Anyone on the same network can access your service using the printed URL.

## Requirements

- Python 3.9+
- `rich` (terminal UI)
- `qrcode` (QR code generation)
