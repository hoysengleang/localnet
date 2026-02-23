# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [0.1.0] - 2025-02-23

### Added

- **share** — Expose local ports on the LAN with a TCP proxy
- **list** — Show all active shares
- **stop** — Stop a share by port or name
- **info** — Display network info (hostname, IP, interfaces)
- **scan** — Discover other localnet-access instances on the LAN
- QR code display for easy mobile access
- IP/CIDR access control (`--allow`, `--deny`)
- Token auth (`--token`) — clients use `?token=` or `Authorization: Bearer`
- HTTP request log (`--http-log`) — live method, path, status, latency
- Keep-alive support so multiple requests per connection are logged
- Broadcast presence via UDP for `localnet scan`

### Platform

- Targets Linux first. macOS may work. Windows not yet supported.
