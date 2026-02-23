from __future__ import annotations

import argparse
import asyncio
import os
import signal
import sys
from datetime import datetime

from localnet_access import __version__
from localnet_access.acl import AccessControl, parse_acl_rule
from localnet_access.display import (
    console,
    print_banner,
    print_error,
    print_http_entry,
    print_network_info,
    print_scan_results,
    print_services_table,
    print_share_info,
    print_success,
)
from localnet_access.network import (
    find_free_port,
    get_local_ip,
    get_network_info,
    is_port_in_use,
    parse_target,
)
from localnet_access.proxy import (
    HttpEntry,
    SharedService,
    cleanup_dead_services,
    remove_service,
    run_proxy,
    save_service,
)
from localnet_access.scanner import broadcast_presence, scan_lan


def _build_acl(args: argparse.Namespace) -> AccessControl:
    acl = AccessControl()
    allow_list: list[str] = args.allow or []
    deny_list: list[str] = args.deny or []
    try:
        for raw in allow_list:
            acl.allow_rules.append(parse_acl_rule(raw))
        for raw in deny_list:
            acl.deny_rules.append(parse_acl_rule(raw))
    except ValueError as e:
        print_error(f"Invalid IP/CIDR rule: {e}")
        sys.exit(1)
    return acl


def _on_connection(ip: str, allowed: bool) -> None:
    ts = datetime.now().strftime("%H:%M:%S")
    if allowed:
        console.print(f"  [dim]{ts}[/dim]  [green]ALLOW[/green]  {ip}")
    else:
        console.print(f"  [dim]{ts}[/dim]  [bold red]DENY [/bold red]  {ip}")


def _on_http(entry: HttpEntry) -> None:
    print_http_entry(entry)


def cmd_share(args: argparse.Namespace) -> None:
    target_host, target_port = parse_target(args.target)

    if not is_port_in_use(target_port, target_host):
        print_error(
            f"Nothing is listening on {target_host}:{target_port}\n"
            f"  Start your service first, then run localnet share again."
        )
        sys.exit(1)

    listen_port = args.port if args.port else target_port

    if is_port_in_use(listen_port, "0.0.0.0") and listen_port != target_port:
        print_error(f"Port {listen_port} is already in use. Try a different port with --port.")
        sys.exit(1)

    if listen_port == target_port and is_port_in_use(listen_port, "0.0.0.0"):
        alt = find_free_port()
        if alt is None:
            print_error("Could not find a free port to listen on.")
            sys.exit(1)
        listen_port = alt

    acl = _build_acl(args)
    token: str = args.token or ""
    http_log: bool = args.http_log

    local_ip = get_local_ip()
    name = args.name or f"service-{target_port}"
    share_url = f"http://{local_ip}:{listen_port}"

    service = SharedService(
        name=name,
        target_host=target_host,
        target_port=target_port,
        listen_port=listen_port,
        local_ip=local_ip,
        pid=os.getpid(),
        started_at=datetime.now().isoformat(timespec="seconds"),
        share_url=share_url,
        allow_rules=[str(r) for r in acl.allow_rules],
        deny_rules=[str(r) for r in acl.deny_rules],
        token=token,
        http_log=http_log,
    )

    save_service(service)
    print_banner()
    print_share_info(service, acl=acl, show_qr=not args.no_qr)

    share_beacon = [{"name": name, "share_url": share_url, "listen_port": listen_port}]

    async def _run() -> None:
        broadcast_task = asyncio.create_task(broadcast_presence(share_beacon))
        try:
            await run_proxy(
                target_host, target_port, listen_port,
                acl=acl,
                token=token,
                http_log=http_log,
                on_connection=_on_connection if not http_log else None,
                on_http=_on_http if http_log else None,
            )
        finally:
            broadcast_task.cancel()
            try:
                await broadcast_task
            except asyncio.CancelledError:
                pass

    try:
        asyncio.run(_run())
    except KeyboardInterrupt:
        pass
    finally:
        remove_service(listen_port)
        print_success(f"Stopped sharing {name}")


def cmd_list(args: argparse.Namespace) -> None:
    print_banner()
    services = cleanup_dead_services()
    print_services_table(services)


def cmd_stop(args: argparse.Namespace) -> None:
    services = cleanup_dead_services()

    target = None
    for svc in services:
        if str(svc.listen_port) == args.target or svc.name == args.target:
            target = svc
            break

    if target is None:
        print_error(f"No active share matching '{args.target}'. Run `localnet list` to see active shares.")
        sys.exit(1)

    try:
        os.kill(target.pid, signal.SIGTERM)
        remove_service(target.listen_port)
        print_success(f"Stopped sharing '{target.name}' (port {target.listen_port})")
    except OSError as e:
        print_error(f"Could not stop process {target.pid}: {e}")
        sys.exit(1)


def cmd_info(args: argparse.Namespace) -> None:
    print_banner()
    info = get_network_info()
    print_network_info(info.hostname, info.local_ip, info.interfaces)


def cmd_scan(args: argparse.Namespace) -> None:
    print_banner()
    console.print(f"\n  [dim]Scanning your network for localnet-access shares ({args.timeout}s)...[/dim]\n")
    shares = scan_lan(timeout=args.timeout)
    print_scan_results(shares)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="localnet",
        description="Share local dev services with anyone on your network",
    )
    parser.add_argument("-v", "--version", action="version", version=f"%(prog)s {__version__}")

    sub = parser.add_subparsers(dest="command", title="commands")

    # ── share ──────────────────────────────────────────────────────────────
    p_share = sub.add_parser(
        "share",
        help="Share a local service on the network",
        description="Expose a local port/service so others on your LAN can access it.",
    )
    p_share.add_argument(
        "target",
        help="Port number or host:port to share (e.g. 3000, localhost:8080)",
    )
    p_share.add_argument("-p", "--port", type=int, default=None,
                         help="Custom listen port (default: same as target)")
    p_share.add_argument("-n", "--name", default=None,
                         help="Friendly name for this share")
    p_share.add_argument("--expose", action="store_true",
                         help="Use the same port as the target")
    p_share.add_argument("--no-qr", action="store_true",
                         help="Don't show QR code")
    p_share.add_argument(
        "--allow", action="append", metavar="IP",
        help="Only allow this IP or CIDR (repeatable)",
    )
    p_share.add_argument(
        "--deny", action="append", metavar="IP",
        help="Block this IP or CIDR (repeatable)",
    )
    p_share.add_argument(
        "--token", default=None, metavar="SECRET",
        help=(
            "Require this token on every HTTP request. "
            "Clients must send 'Authorization: Bearer <token>' or '?token=<token>'"
        ),
    )
    p_share.add_argument(
        "--http-log", action="store_true",
        help="Show live HTTP request log (method, path, status, latency)",
    )
    p_share.set_defaults(func=cmd_share)

    # ── list ───────────────────────────────────────────────────────────────
    p_list = sub.add_parser("list", help="List all active shares")
    p_list.set_defaults(func=cmd_list)

    # ── stop ───────────────────────────────────────────────────────────────
    p_stop = sub.add_parser("stop", help="Stop an active share")
    p_stop.add_argument("target", help="Port number or name of the share to stop")
    p_stop.set_defaults(func=cmd_stop)

    # ── info ───────────────────────────────────────────────────────────────
    p_info = sub.add_parser("info", help="Show network information")
    p_info.set_defaults(func=cmd_info)

    # ── scan ───────────────────────────────────────────────────────────────
    p_scan = sub.add_parser(
        "scan",
        help="Discover other localnet-access shares on your network",
        description="Broadcasts a UDP probe and lists all responding localnet-access instances.",
    )
    p_scan.add_argument(
        "--timeout", type=float, default=2.0, metavar="SECS",
        help="How long to wait for replies (default: 2s)",
    )
    p_scan.set_defaults(func=cmd_scan)

    return parser


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        sys.exit(0)

    args.func(args)


if __name__ == "__main__":
    main()
