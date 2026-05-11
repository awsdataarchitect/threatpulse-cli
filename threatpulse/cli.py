"""ThreatPulse CLI — scan lockfiles for weaponized vulnerabilities."""

import json
import sys
from pathlib import Path

import click
import requests

API_BASE = "https://threatpulse.waltsoft.net"


def parse_lockfile(path: str) -> list[str]:
    """Extract package names from lockfiles."""
    p = Path(path)
    content = p.read_text()

    if p.name == "package-lock.json":
        data = json.loads(content)
        deps = data.get("packages", data.get("dependencies", {}))
        return [k.split("node_modules/")[-1] for k in deps if k]

    if p.name in ("requirements.txt", "constraints.txt"):
        return [l.split("==")[0].split(">=")[0].split("~=")[0].strip()
                for l in content.splitlines() if l.strip() and not l.startswith("#")]

    if p.name == "Cargo.lock":
        return [l.split('"')[1] for l in content.splitlines() if l.startswith('name = "')]

    if p.name in ("go.sum", "go.mod"):
        return [l.split()[0] for l in content.splitlines()
                if l.strip() and not l.startswith("module") and not l.startswith("go ")]

    if p.name == "Gemfile.lock":
        return [l.strip().split()[0] for l in content.splitlines()
                if l.startswith("    ") and not l.strip().startswith("(")]

    # Fallback: one package per line
    return [l.strip() for l in content.splitlines() if l.strip()]


def scan_packages(packages: list[str], threshold: int, payment_key: str | None) -> list[dict]:
    """Call ThreatPulse /v1/scan endpoint."""
    headers = {}
    if payment_key:
        headers["Authorization"] = f"Bearer {payment_key}"

    resp = requests.post(f"{API_BASE}/v1/scan", json={"packages": packages}, headers=headers, timeout=30)

    if resp.status_code == 402:
        # Show pricing info for free tier users
        click.echo("⚡ Free tier: showing cached results only. Set THREATPULSE_KEY for full access.", err=True)
        return []

    if resp.status_code != 200:
        click.echo(f"Error: {resp.status_code} {resp.text}", err=True)
        return []

    return resp.json().get("vulnerabilities", [])


URGENCY_COLORS = {
    "CRITICAL": "red",
    "HIGH": "yellow",
    "MEDIUM": "cyan",
    "LOW": "green",
}

EXPLOIT_ICONS = {
    "weaponized": "🔴",
    "poc": "🟡",
    "none": "🟢",
}


@click.group()
@click.version_option(version="0.2.0", prog_name="threatpulse")
def cli():
    """ThreatPulse — weaponized vulnerability intelligence."""
    pass


@cli.command()
@click.argument("path", default=".")
@click.option("--file", "-f", help="Lockfile path (auto-detected if not specified)")
@click.option("--threshold", "-t", default=0, help="Fail if any CVE urgency >= threshold")
@click.option("--format", "fmt", type=click.Choice(["table", "json", "sarif"]), default="table")
@click.option("--key", envvar="THREATPULSE_KEY", help="Payment key (or set THREATPULSE_KEY env)")
def scan(path: str, file: str | None, threshold: int, fmt: str, key: str | None):
    """Scan dependencies for weaponized vulnerabilities.

    \b
    Examples:
      threatpulse scan .
      threatpulse scan --file package-lock.json --threshold 80
      threatpulse scan --format json | jq '.[] | select(.urgency_score > 70)'
    """
    # Find lockfile
    if file:
        lockfile = file
    else:
        p = Path(path)
        candidates = ["package-lock.json", "yarn.lock", "requirements.txt",
                      "Cargo.lock", "go.sum", "Gemfile.lock", "pnpm-lock.yaml"]
        lockfile = next((str(p / c) for c in candidates if (p / c).exists()), None)
        if not lockfile:
            click.echo("No lockfile found. Use --file to specify.", err=True)
            sys.exit(1)

    click.echo(f"📦 Scanning {lockfile}...", err=True)
    packages = parse_lockfile(lockfile)
    click.echo(f"   Found {len(packages)} packages", err=True)

    vulns = scan_packages(packages, threshold, key)

    if not vulns:
        click.echo("✅ No known vulnerabilities found.", err=True)
        sys.exit(0)

    # Sort by urgency
    vulns.sort(key=lambda v: v.get("urgency_score", 0), reverse=True)

    if fmt == "json":
        click.echo(json.dumps(vulns, indent=2))
    elif fmt == "sarif":
        click.echo(json.dumps(to_sarif(vulns), indent=2))
    else:
        # Table output
        click.echo(f"\n{'CVE':<20} {'Severity':<10} {'Exploit':<12} {'Urgency':<8} {'Package'}", err=True)
        click.echo("─" * 75, err=True)
        for v in vulns:
            icon = EXPLOIT_ICONS.get(v.get("exploit_status", "none"), "⚪")
            sev = v.get("severity", "?")
            color = URGENCY_COLORS.get(sev, "white")
            click.echo(
                f"{icon} {v.get('cve_id', '?'):<18} "
                f"{click.style(sev, fg=color):<19} "
                f"{v.get('exploit_status', '?'):<12} "
                f"{v.get('urgency_score', '?'):<8} "
                f"{', '.join(v.get('affected_products', [])[:2])}"
            , err=True)

    # Exit code based on threshold
    max_urgency = max((v.get("urgency_score", 0) for v in vulns), default=0)
    if threshold > 0 and max_urgency >= threshold:
        click.echo(f"\n❌ FAILED: urgency {max_urgency} >= threshold {threshold}", err=True)
        sys.exit(1)

    click.echo(f"\n⚠️  {len(vulns)} vulnerabilities found (max urgency: {max_urgency})", err=True)


def to_sarif(vulns: list[dict]) -> dict:
    """Convert to SARIF format for GitHub Code Scanning."""
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "ThreatPulse", "version": "0.1.0",
                "informationUri": "https://threatpulse.waltsoft.net"}},
            "results": [{
                "ruleId": v.get("cve_id", ""),
                "level": "error" if v.get("urgency_score", 0) >= 70 else "warning",
                "message": {"text": f"{v.get('cve_id')}: {v.get('exploit_status')} (urgency {v.get('urgency_score')})"},
            } for v in vulns],
        }],
    }


if __name__ == "__main__":
    cli()
