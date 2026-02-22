from __future__ import annotations

from rich import box
from rich.align import Align
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from localnet_access.acl import AccessControl
from localnet_access.proxy import HttpEntry, SharedService
from localnet_access.scanner import RemoteShare

console = Console()

_STATUS_STYLE: dict[int, str] = {}


def _status_style(code: int) -> str:
    if code == 0:
        return "dim"
    if code < 200:
        return "dim"
    if code < 300:
        return "bold green"
    if code < 400:
        return "cyan"
    if code < 500:
        return "bold yellow"
    return "bold red"


def _method_style(method: str) -> str:
    return {
        "GET": "green",
        "POST": "bold cyan",
        "PUT": "yellow",
        "PATCH": "yellow",
        "DELETE": "bold red",
        "HEAD": "dim",
        "OPTIONS": "dim",
    }.get(method.upper(), "white")


def print_banner() -> None:
    banner = Text()
    banner.append("  localnet", style="bold cyan")
    banner.append("-access", style="bold white")
    banner.append("  v0.1.0\n", style="dim")
    banner.append("  Share local services instantly on your network", style="italic dim")
    console.print(Panel(banner, border_style="cyan", padding=(0, 1)))


def print_share_info(
    service: SharedService,
    acl: AccessControl | None = None,
    show_qr: bool = True,
) -> None:
    table = Table(show_header=False, box=box.SIMPLE, padding=(0, 2))
    table.add_column(style="bold cyan", min_width=12)
    table.add_column()

    table.add_row("Service", service.name)
    table.add_row("Target", f"{service.target_host}:{service.target_port}")
    table.add_row("Listen", f"0.0.0.0:{service.listen_port}")
    table.add_row("Share URL", f"[bold green]{service.share_url}[/bold green]")
    table.add_row("PID", str(service.pid))

    if service.token:
        table.add_row("Token", f"[bold yellow]{service.token}[/bold yellow]")

    if service.http_log:
        table.add_row("HTTP Log", "[bold cyan]enabled[/bold cyan]")

    if acl and acl.is_restricted:
        table.add_row("", "")
        table.add_row("Access", f"[bold yellow]{acl.policy.value.upper()}[/bold yellow]")
        for rule_desc in acl.describe_rules():
            if rule_desc.startswith("allow"):
                table.add_row("", f"[green]{rule_desc}[/green]")
            else:
                table.add_row("", f"[red]{rule_desc}[/red]")
    else:
        table.add_row("Access", "[dim]open to all[/dim]")

    console.print()
    console.print(
        Panel(table, title="[bold green]Sharing Active[/bold green]", border_style="green", padding=(1, 2))
    )

    if show_qr:
        _print_qr(service.share_url)

    console.print()
    if service.http_log:
        _print_http_log_header()
    elif acl and acl.is_restricted:
        console.print("  [dim]Connection log:[/dim]")

    console.print()
    console.print("  [dim]Press Ctrl+C to stop sharing[/dim]")
    console.print()


def _print_http_log_header() -> None:
    header = (
        f"  {'TIME':<10} {'IP':<16} {'METHOD':<8} {'PATH':<40} {'STATUS':<8} {'MS':>6}"
    )
    console.print(f"[dim]{header}[/dim]")
    console.print(f"  [dim]{'─' * 90}[/dim]")


def print_http_entry(entry: HttpEntry) -> None:
    """Print one HTTP request log line — called live from the proxy callback."""
    from datetime import datetime

    ts = datetime.now().strftime("%H:%M:%S")
    method_s = f"[{_method_style(entry.method)}]{entry.method:<7}[/{_method_style(entry.method)}]"
    status_s = f"[{_status_style(entry.status)}]{entry.status}[/{_status_style(entry.status)}]"


    path = entry.path if len(entry.path) <= 40 else entry.path[:37] + "..."

    if entry.duration_ms > 0:
        ms_s = f"[dim]{entry.duration_ms:>5.0f}ms[/dim]"
    else:
        ms_s = "[dim]   —  [/dim]"

    console.print(
        f"  [dim]{ts}[/dim]  [dim]{entry.client_ip:<16}[/dim]  "
        f"{method_s}  [white]{path:<40}[/white]  {status_s}  {ms_s}"
    )


def _print_qr(url: str) -> None:
    try:
        import qrcode

        qr = qrcode.QRCode(
            border=2,
            error_correction=qrcode.constants.ERROR_CORRECT_M,
        )
        qr.add_data(url)
        qr.make(fit=True)
        matrix = qr.get_matrix()

        content = Text()
        for row in matrix:
            for cell in row:
                content.append("  ", style="on black" if cell else "on white")
            content.append("\n")

        content.append(f"\n  {url}\n", style="bold green")

        console.print()
        console.print(Panel(
            Align.center(content),
            title="[bold white] Scan to open on mobile [/bold white]",
            border_style="bright_white",
            padding=(0, 1),
            expand=False,
        ))

    except ImportError:
        console.print("  [dim](install 'qrcode' for QR code display)[/dim]")


def print_services_table(services: list[SharedService]) -> None:
    if not services:
        console.print("\n  [yellow]No active shares found.[/yellow]\n")
        return

    table = Table(title="Active Shares", box=box.ROUNDED, border_style="cyan")
    table.add_column("Name", style="bold")
    table.add_column("Target", style="dim")
    table.add_column("Listen Port", justify="center")
    table.add_column("Share URL", style="green")
    table.add_column("Access", justify="center")
    table.add_column("Token", justify="center")
    table.add_column("PID", justify="center", style="dim")

    for svc in services:
        if svc.allow_rules or svc.deny_rules:
            n = len(svc.allow_rules) + len(svc.deny_rules)
            access_str = f"[yellow]{n} rule{'s' if n != 1 else ''}[/yellow]"
        else:
            access_str = "[dim]open[/dim]"

        token_str = "[bold yellow]yes[/bold yellow]" if svc.token else "[dim]—[/dim]"

        table.add_row(
            svc.name,
            f"{svc.target_host}:{svc.target_port}",
            str(svc.listen_port),
            svc.share_url,
            access_str,
            token_str,
            str(svc.pid),
        )

    console.print()
    console.print(table)
    console.print()


def print_scan_results(shares: list[RemoteShare]) -> None:
    """Print discovered LAN shares from `localnet scan`."""
    if not shares:
        console.print("\n  [yellow]No other localnet-access instances found on your network.[/yellow]")
        console.print("  [dim]Make sure others are running `localnet share` on the same LAN.[/dim]\n")
        return

    table = Table(
        title=f"[bold cyan]Found {len(shares)} share{'s' if len(shares) != 1 else ''} on your network[/bold cyan]",
        box=box.ROUNDED,
        border_style="cyan",
    )
    table.add_column("IP", style="dim")
    table.add_column("Name", style="bold")
    table.add_column("Share URL", style="bold green")
    table.add_column("Port", justify="center", style="dim")

    for s in shares:
        table.add_row(s.ip, s.name, s.share_url, str(s.listen_port))

    console.print()
    console.print(table)
    console.print()


def print_network_info(hostname: str, local_ip: str, interfaces: list[dict[str, str]]) -> None:
    table = Table(show_header=False, box=box.SIMPLE, padding=(0, 2))
    table.add_column(style="bold cyan", min_width=12)
    table.add_column()

    table.add_row("Hostname", hostname)
    table.add_row("Primary IP", f"[bold green]{local_ip}[/bold green]")

    for iface in interfaces:
        style = "green" if iface["ip"] == local_ip else "dim"
        table.add_row(f"  {iface['name']}", f"[{style}]{iface['ip']}[/{style}]")

    console.print()
    console.print(Panel(table, title="[bold cyan]Network Info[/bold cyan]", border_style="cyan", padding=(1, 2)))
    console.print()


def print_error(msg: str) -> None:
    console.print(f"\n  [bold red]Error:[/bold red] {msg}\n")


def print_success(msg: str) -> None:
    console.print(f"\n  [bold green]✓[/bold green] {msg}\n")
