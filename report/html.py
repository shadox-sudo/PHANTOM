"""PHANTOM — HTML Report Generator"""
from __future__ import annotations
import logging
import os
from datetime import datetime
from typing import Any

logger = logging.getLogger("phantom.report.html")


class HTMLReport:
    """Generates dark-themed HTML security assessment reports."""

    CSS = """
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Consolas','Courier New',monospace;background:#0a0a0a;color:#d0d0d0;line-height:1.6;padding:0;margin:0}
.container{max-width:1300px;margin:0 auto;padding:30px}
.header{border-bottom:3px solid #00ff41;padding-bottom:25px;margin-bottom:35px}
.header h1{color:#00ff41;font-size:32px;letter-spacing:2px;font-weight:400;text-shadow:0 0 20px rgba(0,255,65,.3)}
.header .meta{color:#888;font-size:13px;margin-top:12px;display:grid;grid-template-columns:auto auto;gap:4px 30px;max-width:600px}
.header .meta span{color:#aaa}
.stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:15px;margin:20px 0}
.stat-card{background:#111;border:1px solid #222;border-radius:6px;padding:20px;text-align:center}
.stat-card .num{font-size:32px;font-weight:700;color:#00ff41}
.stat-card .label{color:#666;font-size:11px;margin-top:5px;text-transform:uppercase;letter-spacing:1px}
.stat-card.critical .num{color:#ff0044}
.stat-card.high .num{color:#ff6600}
.stat-card.medium .num{color:#ffcc00}
.stat-card.low .num{color:#66ccff}
.section{margin:40px 0}
.section h2{color:#00ff41;font-size:20px;font-weight:400;border-bottom:1px solid #1a1a1a;padding-bottom:10px;margin-bottom:20px;letter-spacing:1px}
.card{background:#111;border:1px solid #222;border-radius:6px;padding:18px;margin:12px 0}
.card.critical{border-left:4px solid #ff0044}
.card.high{border-left:4px solid #ff6600}
.card.medium{border-left:4px solid #ffcc00}
.card.low{border-left:4px solid #66ccff}
.card.info{border-left:4px solid #666}
.card p{margin:6px 0;color:#aaa;font-size:13px}
.severity-badge{display:inline-block;padding:3px 10px;border-radius:3px;font-size:11px;font-weight:700;letter-spacing:1px;margin-right:8px}
.severity-badge.critical{background:#ff0044;color:#fff}
.severity-badge.high{background:#ff6600;color:#fff}
.severity-badge.medium{background:#ffcc00;color:#111}
.severity-badge.low{background:#66ccff;color:#111}
.severity-badge.info{background:#444;color:#ccc}
table{width:100%;border-collapse:collapse;margin:10px 0;font-size:13px}
th,td{padding:10px 12px;text-align:left;border-bottom:1px solid #1a1a1a}
th{background:#0d0d0d;color:#00ff41;font-weight:400}
code{background:#0d0d0d;padding:2px 8px;border-radius:3px;font-family:'Consolas',monospace;font-size:12px;color:#ffcc00;word-break:break-all}
pre{background:#0d0d0d;padding:15px;border-radius:4px;overflow-x:auto;font-size:12px;color:#aaa;border:1px solid #1a1a1a;max-height:300px;overflow-y:auto}
.timeline{position:relative;padding-left:25px}
.timeline::before{content:'';position:absolute;left:8px;top:0;bottom:0;width:2px;background:#1a1a1a}
.timeline-item{padding:8px 0 8px 20px;border-left:2px solid #333;margin:6px 0;position:relative;font-size:13px}
.timeline-item::before{content:'';position:absolute;left:-7px;top:12px;width:10px;height:10px;border-radius:50%;background:#333;border:2px solid #0a0a0a}
.timeline-item.success::before{background:#00ff41}
.timeline-item.failed::before{background:#ff0044}
.timeline-item .time{color:#555;font-size:11px}
.timeline-item .phase-tag{display:inline-block;padding:1px 6px;border-radius:2px;font-size:10px;background:#1a1a1a;color:#666;margin:0 5px}
.tech-badge{display:inline-block;padding:4px 12px;border-radius:3px;font-size:12px;background:#1a1a1a;color:#aaa;border:1px solid #2a2a2a;margin:3px}
.tech-badge .ver{color:#666;font-size:10px}
.footer{margin-top:60px;padding-top:25px;border-top:1px solid #1a1a1a;color:#444;font-size:12px;text-align:center}
.text-muted{color:#666}
"""

    def __init__(self, engine) -> None:
        self.engine = engine
        self.config = getattr(engine, "config", None)
        self.target = getattr(engine, "target", None)
        self.findings = getattr(engine, "findings", None)

    def generate(self) -> str:
        """Generate HTML report and write to file.

        Returns:
            Path to saved HTML file.
        """
        if not self.target:
            logger.error("No target data to generate report")
            return ""
        html = self._build()
        return self._save(html)

    # ── HTML Builder ───────────────────────────────────────────

    def _build(self) -> str:
        t = self.target
        domain = getattr(t, "domain", "") or getattr(t, "url", "") or getattr(t, "ip", "unknown")
        scan_date = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
        dur = self._duration()

        return f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>PHANTOM Security Report — {domain}</title>
<style>{self.CSS}</style></head>
<body><div class="container">
{self._header(domain, scan_date, dur)}
{self._stats()}
{self._recon()}
{self._vulns()}
{self._exploits()}
{self._timeline()}
{self._footer(scan_date)}
</div></body></html>"""

    # ── Header ─────────────────────────────────────────────────

    def _header(self, domain: str, scan_date: str, dur: str) -> str:
        t = self.target
        ip = getattr(t, "ip", "") or ""
        return f"""<div class="header">
<h1>PHANTOM Security Assessment Report</h1>
<div class="subtitle" style="color:#666;font-size:14px;margin-top:5px">Autonomous Penetration Testing Framework</div>
<div class="meta">
<div><span>Target:</span> {domain}</div><div><span>Generated:</span> {scan_date}</div>
<div><span>IP Address:</span> {ip or "N/A"}</div><div><span>Duration:</span> {dur}</div>
</div></div>"""

    # ── Stats ──────────────────────────────────────────────────

    def _stats(self) -> str:
        fl = self.findings.all() if self.findings else []
        t = self.target

        sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in fl:
            sev[f.severity.upper()] = sev.get(f.severity.upper(), 0) + 1

        ports = len(getattr(t, "ports", []) or getattr(t, "open_ports", []))
        subs = len(getattr(t, "subdomains", []))
        tech = len(getattr(t, "tech_stack", []))
        dirs = len(getattr(t, "directories", []))
        exps = len(getattr(t, "exploits", []))

        def sc(label: str, num: int, cls: str = "") -> str:
            return f'<div class="stat-card {cls}"><div class="num">{num}</div><div class="label">{label}</div></div>'

        return f"""<div class="section"><h2>Executive Summary</h2>
<div class="stats-grid">
{sc("Findings", len(fl))}{sc("Critical", sev["CRITICAL"], "critical")}
{sc("High", sev["HIGH"], "high")}{sc("Medium", sev["MEDIUM"], "medium")}
{sc("Low", sev["LOW"], "low")}{sc("Open Ports", ports)}
{sc("Subdomains", subs)}{sc("Technologies", tech)}
{sc("Directories", dirs)}{sc("Exploit PoCs", exps)}
</div></div>"""

    # ── Recon ──────────────────────────────────────────────────

    def _recon(self) -> str:
        t = self.target
        html = '<div class="section"><h2>Reconnaissance Results</h2>'

        # Ports
        html += '<div class="card"><h3>Open Ports</h3>'
        ports = getattr(t, "ports", []) or getattr(t, "open_ports", [])
        if ports:
            html += '<table><tr><th>Port</th><th>Service</th><th>Banner</th></tr>'
            for p in ports:
                pnum = getattr(p, "port", p) if not isinstance(p, dict) else p.get("port", p)
                svc = getattr(p, "service", "") if not isinstance(p, dict) else p.get("service", "")
                ban = getattr(p, "banner", "") if not isinstance(p, dict) else p.get("banner", "")
                html += f"<tr><td>{pnum}</td><td>{svc or '?'}</td><td><code>{ban or ''}</code></td></tr>"
            html += "</table>"
        else:
            html += '<p class="text-muted">No open ports discovered.</p>'
        html += "</div>"

        # Tech Stack
        html += '<div class="card"><h3>Technology Stack</h3>'
        tech = getattr(t, "tech_stack", [])
        items: list[tuple[str, str]] = []
        if isinstance(tech, dict):
            items = list(tech.items())
        elif isinstance(tech, list):
            items = [(getattr(x, "name", x) if not isinstance(x, dict) else x.get("name", x),
                      getattr(x, "version", "") if not isinstance(x, dict) else x.get("version", "")) for x in tech]
        if items:
            for name, ver in tech.items() if isinstance(tech, dict) else items:
                v = f' <span class="ver">{ver}</span>' if ver else ""
                html += f'<span class="tech-badge">{name}{v}</span>'
        else:
            html += '<p class="text-muted">No technologies identified.</p>'
        html += "</div>"

        # Subdomains
        html += '<div class="card"><h3>Subdomains</h3>'
        subs = getattr(t, "subdomains", [])
        if subs:
            html += '<table><tr><th>Subdomain</th><th>IP</th></tr>'
            for s in subs:
                name = getattr(s, "subdomain", s) if not isinstance(s, dict) else s.get("subdomain", s)
                ip = getattr(s, "ip", "") if not isinstance(s, dict) else s.get("ip", "")
                html += f"<tr><td>{name}</td><td>{ip or '—'}</td></tr>"
            html += "</table>"
        else:
            html += '<p class="text-muted">No subdomains discovered.</p>'
        html += "</div>"

        # Directories
        html += '<div class="card"><h3>Discovered Directories</h3>'
        dirs = getattr(t, "directories", [])
        if dirs:
            html += "".join(f"<code>{d}</code> " for d in dirs)
        else:
            html += '<p class="text-muted">No directories discovered.</p>'
        html += "</div>"

        # JS Endpoints
        html += '<div class="card"><h3>JavaScript Endpoints</h3>'
        js = getattr(t, "js_endpoints", [])
        if js:
            html += "".join(f"<code>{ep}</code> " for ep in js)
        else:
            html += '<p class="text-muted">No JS endpoints extracted.</p>'
        html += "</div></div>"
        return html

    # ── Vulnerabilities ────────────────────────────────────────

    def _vulns(self) -> str:
        fl = self.findings.all() if self.findings else []
        html = '<div class="section"><h2>Vulnerability Findings</h2>'
        if not fl:
            return html + '<p class="text-muted">No vulnerabilities detected.</p></div>'

        for f in fl:
            sev = f.severity.lower()
            param = getattr(f, "param", "") or getattr(f, "parameter", "")
            payload = getattr(f, "payload", "") or ""
            evidence = getattr(f, "evidence", "") or getattr(f, "proof", "") or ""
            cve = getattr(f, "cve", "") or getattr(f, "cve_id", "") or ""
            phase = getattr(f, "phase", "") or ""
            desc = getattr(f, "description", "") or ""

            html += f'<div class="card {sev}">'
            html += f'<span class="severity-badge {sev}">{f.severity.upper()}</span>'
            if phase:
                html += f'<span class="phase-badge" style="display:inline-block;padding:2px 8px;border-radius:3px;font-size:10px;font-weight:700;background:#1a1a1a;color:#888;margin-right:5px">{phase.upper()}</span>'
            html += f'<strong>{f.name}</strong>'
            if desc:
                html += f"<p>{desc}</p>"
            html += f'<p><strong>URL:</strong> <code>{f.url}</code></p>'
            if param:
                html += f'<p><strong>Parameter:</strong> <code>{param}</code></p>'
            if payload:
                html += f'<p><strong>Payload:</strong> <code>{payload}</code></p>'
            if cve:
                html += f"<p><strong>CVE:</strong> {cve}</p>"
            if evidence:
                html += f"<pre>{evidence[:300]}</pre>" if len(evidence) > 300 else f"<pre>{evidence}</pre>"
            html += "</div>"
        return html + "</div>"

    # ── Exploit Commands ───────────────────────────────────────

    def _exploits(self) -> str:
        t = self.target
        exploits = getattr(t, "exploits", [])
        if not exploits:
            return ""

        html = '<div class="section"><h2>Exploit PoC Commands</h2><div class="card">'
        for cmd in exploits:
            if cmd.startswith("#"):
                html += f'<p class="text-muted">{cmd[1:].strip()}</p>'
            else:
                html += f"<pre>{cmd}</pre>"
        return html + "</div></div>"

    # ── Timeline ───────────────────────────────────────────────

    def _timeline(self) -> str:
        tl = getattr(self.target, "timeline", [])
        if not tl:
            return ""

        html = '<div class="section"><h2>Scan Timeline</h2><div class="timeline">'
        for entry in tl:
            ts = entry.get("timestamp", entry.get("time", "")) if isinstance(entry, dict) else getattr(entry, "timestamp", "")
            phase = entry.get("phase", "") if isinstance(entry, dict) else getattr(entry, "phase", "")
            action = entry.get("action", entry.get("detail", "")) if isinstance(entry, dict) else getattr(entry, "action", "")
            status = entry.get("status", "success") if isinstance(entry, dict) else getattr(entry, "status", "success")

            ts_str = ts.strftime("%H:%M:%S") if hasattr(ts, "strftime") else str(ts)[:19] if ts else ""
            cls = "success" if status in ("success", "completed", "done") else "failed" if status in ("failed", "error") else "running"

            html += f'<div class="timeline-item {cls}"><span class="time">{ts_str}</span><span class="phase-tag">{phase}</span>{action} <span class="text-muted">({status})</span></div>'
        return html + "</div></div>"

    # ── Footer ─────────────────────────────────────────────────

    def _footer(self, scan_date: str) -> str:
        return f"""<div class="footer">
<p>Generated by PHANTOM Autonomous Pentest Framework — {scan_date}</p>
<p>This report contains sensitive security information. Handle with care.</p>
</div>"""

    # ── Helpers ────────────────────────────────────────────────

    def _duration(self) -> str:
        tl = getattr(self.target, "timeline", [])
        if len(tl) < 2:
            return "N/A"

        def get_ts(e):
            return e.get("timestamp", e.get("time", "")) if isinstance(e, dict) else getattr(e, "timestamp", "")
        t1, t2 = get_ts(tl[0]), get_ts(tl[-1])
        if t1 and t2:
            try:
                secs = (t2 - t1).total_seconds() if hasattr(t1, "timestamp") else \
                       (datetime.fromisoformat(str(t2)) - datetime.fromisoformat(str(t1))).total_seconds()
                return f"{secs:.1f}s" if secs < 60 else f"{secs/60:.1f}m {secs%60:.0f}s"
            except Exception:
                pass
        return "N/A"

    def _save(self, html: str) -> str:
        t = self.target
        domain = getattr(t, "domain", "") or getattr(t, "url", "") or getattr(t, "ip", "unknown")
        domain = domain.replace("https://", "").replace("http://", "").replace("/", "_")

        out = getattr(getattr(self.config, "report", None), "output_dir", None) or \
              getattr(self.config, "output_dir", "./reports")
        os.makedirs(out, exist_ok=True)
        path = os.path.join(out, f"{domain}_report_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.html")
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(html)
            logger.info("HTML report saved: %s", path)
            return path
        except OSError as e:
            logger.error("Failed to write report: %s", e)
            return ""
