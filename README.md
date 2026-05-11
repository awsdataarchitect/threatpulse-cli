# ThreatPulse CLI

Scan your dependencies for **weaponized** vulnerabilities. Powered by [threatpulse.waltsoft.net](https://threatpulse.waltsoft.net).

## Install

```bash
pip install threatpulse
```

## Authentication

ThreatPulse requires an API key for CLI usage. Purchase at [threatpulse.waltsoft.net](https://threatpulse.waltsoft.net).

```bash
# Set once (recommended)
export THREATPULSE_KEY=tp_live_your_key_here

# Or pass per-command
threatpulse scan --key tp_live_your_key_here
```

**Lost your key?** Recover it at `https://threatpulse.waltsoft.net/key/recover` with your purchase email.

**Check balance:**
```bash
curl -H "Authorization: Bearer tp_live_..." https://threatpulse.waltsoft.net/key/balance
```

## Usage

```bash
# Scan a lockfile
threatpulse scan --file package-lock.json

# Fail CI if urgency >= 80
threatpulse scan --threshold 80

# JSON output for piping
threatpulse scan --format json | jq '.[] | select(.urgency_score > 70)'

# SARIF for GitHub Code Scanning
threatpulse scan --format sarif > results.sarif
```

## What makes this different

Unlike Trivy/Snyk/Inspector, ThreatPulse tells you if a CVE is **actively weaponized**:

```
🔴 CVE-2024-45257   HIGH       weaponized   95   metasploit:exploit/unix/webapp/byob_unauth_rce
🟡 CVE-2025-1234    MEDIUM     poc          45   github.com/user/CVE-2025-1234
🟢 CVE-2025-5678    LOW        none         12   no known exploit
```

## Supported lockfiles

- `package-lock.json` (npm)
- `requirements.txt` (pip)
- `Cargo.lock` (Rust)
- `go.sum` (Go)
- `Gemfile.lock` (Ruby)

## GitHub Action

```yaml
- uses: awsdataarchitect/threatpulse-action@v1
  with:
    fail-on-urgency: 80
```

## Links

- API: https://threatpulse.waltsoft.net
- GitHub: https://github.com/awsdataarchitect/threatpulse-cli
