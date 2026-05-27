# PHANTOM

**Autonomous Penetration Testing Framework**

Recon -> Vulnerability Detection -> Exploit PoC -> Report

---

## What it does

PHANTOM is a pure-Python tool that automates the boring parts of a pentest. Point it at a domain, it runs through the full pipeline: find subdomains, scan ports, fingerprint tech, brute-force directories, then test for vulnerabilities — SQLi, XSS, LFI, SSRF, IDOR, CORS, JWT, rate-limit bypass, default creds, and known CVEs. If it finds something, it generates exploit PoC commands. Finally, it spits out a dark-themed HTML report.

## How to use

```bash
# Full scan
python3 phantom.py example.com --threads 30

# Just recon
python3 phantom.py example.com --phase recon

# Skip slow stuff
python3 phantom.py example.com --no-ports --no-dirs --no-dorks

# Use a proxy (SOCKS5 or HTTP)
python3 phantom.py example.com --proxy socks5://127.0.0.1:9050

# Quiet mode (just results, no banner)
python3 phantom.py example.com --quiet

# Import/export target state between phases
python3 phantom.py example.com --phase recon --export target.json
python3 phantom.py target.json --phase vuln --import target.json

# Telegram notifications
python3 phantom.py example.com --telegram-token TOKEN --telegram-chat-id ID
```

All flags also work via `PHANTOM_*` env vars.

## Pipeline

1. **Recon** — DNS records, WHOIS, subdomain brute-force (crt.sh + wordlist), port scanning (multi-threaded TCP connect), tech fingerprinting (headers + body), directory brute-force, JS scraping, Google dork generation
2. **Vulnerability Detection** — SQLi (error/boolean/time), XSS (reflected), LFI/RFI, SSRF, open redirect, IDOR, JWT analysis (alg none, weak HMAC, sensitive data), CORS misconfig, rate-limit testing, default credentials, CVE matching
3. **Exploit** — picks the best finding, generates ready-to-run PoC commands (sqlmap, curl, etc.)
4. **Report** — HTML with severity badges + timeline, JSON export

## What it is NOT

This is NOT a script-kiddie button. It does not auto-exploit or drop shells. Every finding still needs human verification. Consider it a force multiplier — it handles the enumeration so you can focus on what matters.

## Requirements

- Python 3.10+
- `requests` library (only non-stdlib dependency)
- No AI. No bloated dependencies. No nonsense.

## Live Status

Every module shows a live spinner + elapsed time in the terminal so you know something is actually happening during long scans.

```
  [done] [1/6] DNSRecon (5.6s) — 27 results
  [done] [2/6] PortScanner (34.2s) — 5 results
```

## Output

All reports go to `./reports/` by default. HTML reports are self-contained (no JS, no external CSS) — open them in any browser.

## Design

27+ files, each under 500 lines. Pure Python. Every module self-registers. Everything is in-memory, serialized to JSON at the report phase. No database. No config file required.

## Why

Built for learning. Built for labs. Built to save time.
