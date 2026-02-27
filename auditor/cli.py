"""CLI entrypoint for AWS Security Auditor — powered by Rich for beautiful output."""
import argparse
import sys
import boto3
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.panel import Panel
from rich import box
from rich.text import Text
from .iam_auditor import IAMAuditor
from .s3_auditor import S3Auditor
from .ec2_auditor import EC2Auditor
from .cloudtrail_auditor import CloudTrailAuditor
from .reporter import Reporter

console = Console()

SEVERITY_STYLES = {
    "CRITICAL": "bold red",
    "HIGH":     "bold yellow",
    "MEDIUM":   "bold cyan",
    "LOW":      "dim white",
    "OK":       "bold green",
    "INFO":     "dim cyan",
}


def build_session(profile: str = None, region: str = "us-east-1") -> boto3.Session:
    kwargs = {"region_name": region}
    if profile:
        kwargs["profile_name"] = profile
    return boto3.Session(**kwargs)


def print_findings_table(findings: list):
    """Render findings as a rich table."""
    if not findings:
        console.print(Panel("[bold green]✅  No findings — environment looks clean![/]", border_style="green"))
        return

    table = Table(
        box=box.ROUNDED,
        show_header=True,
        header_style="bold cyan",
        border_style="dim cyan",
        title="[bold]AWS Security Findings[/bold]",
        title_style="bold white",
        expand=True,
    )
    table.add_column("Severity", width=10, justify="center")
    table.add_column("Check", style="bold white", min_width=28)
    table.add_column("Resource", style="dim white", min_width=20)
    table.add_column("Message", style="white")

    for f in findings:
        sev = f.get("severity", "?")
        style = SEVERITY_STYLES.get(sev, "white")
        table.add_row(
            Text(sev, style=style),
            f.get("check", ""),
            f.get("resource", ""),
            f.get("message", ""),
        )

    console.print(table)

    # Summary bar
    counts = {}
    for f in findings:
        s = f.get("severity", "?")
        counts[s] = counts.get(s, 0) + 1

    summary_parts = []
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "OK"]:
        if sev in counts:
            style = SEVERITY_STYLES[sev]
            summary_parts.append(f"[{style}]{sev}: {counts[sev]}[/{style}]")
    console.print("  " + "  │  ".join(summary_parts))
    console.print()


def main():
    parser = argparse.ArgumentParser(
        description="🔐 AWS Security Auditor — by SW1ZX",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  aws-audit                            # Run all checks, terminal output
  aws-audit --checks iam s3           # Run specific checks
  aws-audit --output json             # Output JSON
  aws-audit --output markdown --report-file report.md
  aws-audit --profile prod --region ap-southeast-1
        """,
    )
    parser.add_argument("--profile", help="AWS CLI profile name", default=None)
    parser.add_argument("--region", help="AWS region (default: us-east-1)", default="us-east-1")
    parser.add_argument(
        "--checks",
        nargs="+",
        choices=["iam", "s3", "ec2", "cloudtrail", "all"],
        default=["all"],
        help="Which checks to run (default: all)",
    )
    parser.add_argument(
        "--output",
        choices=["terminal", "json", "markdown"],
        default="terminal",
        help="Output format (default: terminal)",
    )
    parser.add_argument("--report-file", help="Output file path for json/markdown reports")
    args = parser.parse_args()

    # Cyberpunk Hacker Aesthetic Banner
    BANNER = """
    █████╗ ███████╗██╗   ██╗███╗   ██╗██████╗ 
    ██╔══██╗██╔════╝██║   ██║████╗  ██║██╔══██╗
    ███████║███████╗██║   ██║██╔██╗ ██║██║  ██║
    ██╔══██║╚════██║██║   ██║██║╚██╗██║██║  ██║
    ██║  ██║███████║╚██████╔╝██║ ╚████║██████╔╝
    ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═══╝╚═════╝ 
    """
    
    if args.output != "json":
        console.print(Text(BANNER, style="bold cyan"))
        console.print(Panel.fit(
            "[bold cyan]🔐 AWS Security Auditor v2.0[/bold cyan]\n"
            "[dim white]Aggressive Cloud Recon & Misconfiguration Scanner[/dim white]\n"
            "[dim]by SW1ZX | github.com/anousonephyakeo[/dim]",
            border_style="magenta",
            box=box.HEAVY
        ))

    try:
        session = build_session(args.profile, args.region)
    except Exception as e:
        console.print(f"[red]❌  Failed to create AWS session: {e}[/red]")
        sys.exit(1)

    all_findings = []
    run_all = "all" in args.checks

    checkers = []
    if run_all or "iam" in args.checks:
        checkers.append(("IAM", IAMAuditor))
    if run_all or "s3" in args.checks:
        checkers.append(("S3", S3Auditor))
    if run_all or "ec2" in args.checks:
        checkers.append(("EC2", EC2Auditor))
    if run_all or "cloudtrail" in args.checks:
        checkers.append(("CloudTrail", CloudTrailAuditor))

    if args.output != "json":
        with Progress(
            SpinnerColumn(style="cyan"),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(bar_width=30, style="cyan", complete_style="bright_cyan"),
            console=console,
            transient=True,
        ) as progress:
            task = progress.add_task("Running checks...", total=len(checkers))
            for name, CheckerClass in checkers:
                progress.update(task, description=f"[cyan]Running {name} checks...")
                findings = CheckerClass(session).run_all()
                all_findings.extend(findings)
                progress.advance(task)
    else:
        for name, CheckerClass in checkers:
            findings = CheckerClass(session).run_all()
            all_findings.extend(findings)

    reporter = Reporter(all_findings)

    if args.output == "json":
        output = reporter.to_json(args.report_file)
        if not args.report_file:
            console.print(output)
        else:
            console.print(f"[green]✅  Report saved to {args.report_file}[/green]")
    elif args.output == "markdown":
        output = reporter.to_markdown(args.report_file)
        if not args.report_file:
            console.print(output)
        else:
            console.print(f"[green]✅  Report saved to {args.report_file}[/green]")
    else:
        print_findings_table(reporter.findings)

    critical = sum(1 for f in all_findings if f.get("severity") == "CRITICAL")
    if critical > 0:
        if args.output != "json":
            console.print(f"[bold red]🚨  {critical} CRITICAL finding(s) — immediate action required![/bold red]")
        sys.exit(1)
    else:
        if args.output != "json":
            console.print("[bold green]✅  Scan complete — no critical findings.[/bold green]")
        sys.exit(0)


if __name__ == "__main__":
    main()
