# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Fixed

- Token-protected proxy mode now correctly handles chunked and connection-close HTTP bodies, preventing timeouts/truncated responses.
- Token mode now authenticates the first request then switches to transparent stream forwarding, improving compatibility with tunnel streaming and long-lived connections.
- Token mode now uses the same transparent-stream path even when `--http-log` is enabled, avoiding tunnel stream errors from strict per-request parsing.
- Unauthorized requests in token mode now return `401` and close immediately instead of waiting for another request on the same socket.
- Valid `?token=...` requests now issue a `localnet_token` cookie so follow-up browser requests work without repeating the query token.
- When a `?token=` query is explicitly provided, it must match the configured token even if a valid auth cookie already exists.
- Auth cookies are now signed per-process and cleared on `401`, so stale cookies from previous runs cannot be reused.
- Tunnel startup now waits for a Cloudflare connection registration signal when available, reducing early-access race conditions.
- CLI now prints the full tunnel public URL explicitly (outside table truncation), making copy/paste reliable.
- Banner version now reflects the package version dynamically.

## [0.2.0] - 2026-03-04

### Added

- `localnet share --tunnel` to create a public URL via Cloudflare Tunnel (`cloudflared`)
- Auto-download and cache `cloudflared` for `--tunnel` when it's missing in PATH

## [0.1.0] - 2025-02-23

### Added

- **share** — Expose local ports on the LAN with a TCP proxy
- **list** — Show all active shares
- **stop** — Stop a share by port or name
- **info** — Display network info (hostname, IP, interfaces)
- **scan** — Discover other localnet-control instances on the LAN
- QR code display for easy mobile access
- IP/CIDR access control (`--allow`, `--deny`)
- Token auth (`--token`) — clients use `?token=` or `Authorization: Bearer`
- HTTP request log (`--http-log`) — live method, path, status, latency
- Keep-alive support so multiple requests per connection are logged
- Broadcast presence via UDP for `localnet scan`

### Platform

- Targets Linux first. macOS may work. Windows not yet supported.
