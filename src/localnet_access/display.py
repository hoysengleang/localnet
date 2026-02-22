from __future__ import annotations

from rich import box
from rich.align import Align
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from localnet_access.acl import AccessControl
from localnet_access.proxy import SharedService

console = Console()


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

    if acl and acl.is_restricted:
        console.print()
        console.print("  [dim]Connection log:[/dim]")

    console.print()
    console.print("  [dim]Press Ctrl+C to stop sharing[/dim]")
    console.print()


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
    table.add_column("PID", justify="center", style="dim")

    for svc in services:
        if svc.allow_rules or svc.deny_rules:
            n_rules = len(svc.allow_rules) + len(svc.deny_rules)
            access_str = f"[yellow]{n_rules} rule{'s' if n_rules != 1 else ''}[/yellow]"
        else:
            access_str = "[dim]open[/dim]"

        table.add_row(
            svc.name,
            f"{svc.target_host}:{svc.target_port}",
            str(svc.listen_port),
            svc.share_url,
            access_str,
            str(svc.pid),
        )

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
