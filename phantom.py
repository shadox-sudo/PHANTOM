#!/usr/bin/env python3
"""
PHANTOM — Autonomous Penetration Testing Framework
Pipeline: Recon -> Vulnerability Detection -> Exploit -> Report

Usage:
  python phantom.py example.com
  python phantom.py example.com --phase recon --threads 50
  python phantom.py example.com --proxy socks5://127.0.0.1:9050
  python phantom.py example.com --phase vuln --import target.json
"""

import sys
import os
import argparse
import builtins
import time as time_module

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_ROOT)


def patch_print():
    """Replace builtins.print with thread-safe version for spinner compatibility."""
    from utils.status import safe_print
    builtins.print = safe_print


def build_parser():
    p = argparse.ArgumentParser(prog="phantom", description="PHANTOM — Autonomous Pentest Framework")
    p.add_argument("target", nargs="?", help="Domain, URL, or IP")
    p.add_argument("--phase", choices=["recon","vuln","exploit","report","all"], default="all")
    p.add_argument("--import", dest="import_path", metavar="FILE", help="Import target state")
    p.add_argument("--export", metavar="FILE", help="Export target state")
    p.add_argument("--threads", type=int, metavar="N", help="Threads (default: 20)")
    p.add_argument("--timeout", type=int, metavar="SEC", help="Timeout (default: 10)")
    p.add_argument("--rate-limit", type=float, metavar="RPS", help="Req/sec (default: 2)")
    p.add_argument("--proxy", metavar="URL", help="Proxy (socks5://... or http://...)")
    p.add_argument("--output", "-o", metavar="DIR", default="./reports", help="Output dir")
    p.add_argument("--quiet", "-q", action="store_true", help="Quiet mode")
    p.add_argument("--telegram-token", metavar="TOKEN")
    p.add_argument("--telegram-chat-id", metavar="ID")

    for flag in ("dns","ports","tech","dirs","js","dorks"):
        p.add_argument(f"--no-{flag}", action="store_true", help=f"Skip {flag}")
    for flag in ("sqli","xss","lfi","ssrf","redirect","idor","jwt","cors","rate-limit","default-creds","cve"):
        p.add_argument(f"--no-{flag}", action="store_true", help=f"Skip {flag}")
    p.add_argument("--no-html", action="store_true", help="Skip HTML report")
    p.add_argument("--no-json", action="store_true", help="Skip JSON report")
    return p


def build_config(args):
    from core.config import PhantomConfig
    c = PhantomConfig()
    c.target = args.target or ""
    c.phases = ["recon","vuln","exploit","report"] if args.phase == "all" else [args.phase]
    if args.threads: c.threads = args.threads
    if args.timeout: c.timeout = args.timeout
    if args.rate_limit: c.rate_limit = args.rate_limit
    if args.proxy: c.proxy = args.proxy
    if args.output: c.output_dir = args.output
    if args.telegram_token: c.telegram_token = args.telegram_token
    if args.telegram_chat_id: c.telegram_chat_id = args.telegram_chat_id

    c.recon_dns = not args.no_dns; c.recon_ports = not args.no_ports
    c.recon_tech = not args.no_tech; c.recon_dirs = not args.no_dirs
    c.recon_js = not args.no_js; c.recon_dorks = not args.no_dorks
    c.vuln_sqli = not args.no_sqli; c.vuln_xss = not args.no_xss
    c.vuln_lfi = not args.no_lfi; c.vuln_ssrf = not args.no_ssrf
    c.vuln_redirect = not args.no_redirect; c.vuln_idor = not args.no_idor
    c.vuln_jwt = not args.no_jwt; c.vuln_cors = not args.no_cors
    c.vuln_rate_limit = not args.no_rate_limit
    c.vuln_default_creds = not args.no_default_creds; c.vuln_cve = not args.no_cve
    c.report_html = not args.no_html; c.report_json = not args.no_json
    c.merge_env()
    return c


def print_summary(engine, out_dir):
    t = engine.target
    fd = engine.findings
    if not t: return

    from utils.status import C
    ports = len(t.ports)
    subs = len(t.subdomains)
    tech = len(t.tech_stack)
    dirs = len(t.directories)
    exps = len(t.exploits)

    sev_counts = {}
    vc = 0
    if fd:
        for f in fd.all():
            s = f.severity.upper()
            sev_counts[s] = sev_counts.get(s, 0) + 1
            vc += 1

    lines = []
    lines.append(f"\n{C.BOLD}{'='*56}{C.RST}")
    lines.append(f" {C.BOLD}SCAN COMPLETE{C.RST} \u2014 {C.CYN}{t.domain or t.ip or '?'}{C.RST}")
    lines.append(f"{C.BOLD}{'='*56}{C.RST}")
    lines.append(f"\n {C.BOLD}Recon:{C.RST}   ports={ports}  subs={subs}  tech={tech}  dirs={dirs}")

    if vc == 0:
        lines.append(f"\n {C.DIM}No vulnerabilities found{C.RST}")
    else:
        lines.append(f"\n {C.BOLD}Findings:{C.RST} {vc} total")
        for sev in ("CRITICAL","HIGH","MEDIUM","LOW","INFO"):
            n = sev_counts.get(sev, 0)
            if n:
                clr = C.RED if sev=="CRITICAL" else C.YLW if sev=="HIGH" else C.BLU if sev=="MEDIUM" else C.DIM
                lines.append(f"   {clr}{sev:>8}: {n}{C.RST}")

    if exps:
        lines.append(f"\n {C.YLW}!{C.RST} {exps} exploit PoC(s) generated")
    lines.append(f"\n {C.CYN}@{C.RST} {out_dir}/")
    lines.append(f"{C.BOLD}\u2500"*56 + C.RST)
    print("\n".join(lines))


def main():
    parser = build_parser()
    args = parser.parse_args()

    from utils.status import C, print_banner
    if not args.quiet:
        print_banner()

    if not args.import_path and not args.target:
        parser.print_help()
        print(f"\n{C.RED}[!]{C.RST} No target specified")
        return 1

    os.makedirs(args.output, exist_ok=True)
    config = build_config(args)

    from core.target import Target
    from core.engine import PhantomEngine

    if args.import_path:
        target = Target.from_json(args.import_path)
    elif args.target:
        ts = args.target.strip()
        if ts.startswith(("http://","https://")):
            target = Target(domain=ts)
        elif "." in ts:
            target = Target(domain=ts)
        else:
            target = Target(domain=ts, ip=ts)
    else:
        target = Target(domain="unknown")

    patch_print()

    engine = PhantomEngine(config)
    engine.target = target

    bot = None
    if config.telegram_token and config.telegram_chat_id:
        try:
            from tg_bot.bot import TelegramBot
            bot = TelegramBot(config.telegram_token, config.telegram_chat_id)
            engine.bot = bot
            bot.start_polling(engine)
        except Exception as e:
            print(f"  {C.YLW}[!]{C.RST} Telegram bot failed: {e}")

    start = time_module.time()
    try:
        engine.run()
        elapsed = time_module.time() - start
        if not args.quiet:
            print_summary(engine, args.output)
        else:
            fc = len(engine.findings.all()) if engine.findings else 0
            print(f"[PHANTOM] {fc} findings in {elapsed:.1f}s")

        if args.export:
            engine.target.to_json(args.export)
    except KeyboardInterrupt:
        print(f"\n{C.YLW}[!] Interrupted{C.RST}")
        return 130
    except Exception as e:
        print(f"\n{C.RED}[!] {e}{C.RST}")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
