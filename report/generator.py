"""
PHANTOM — HTML Report Generator

Builds comprehensive HTML reports from target and report data.
Pure HTML output — no JavaScript dependencies.
"""
from __future__ import annotations
import json
import logging
import os
from datetime import datetime
from typing import Optional

logger = logging.getLogger("phantom.report.generator")


class ReportGenerator:
    """Generates HTML reports from scan data."""

    def __init__(self, config=None) -> None:
        self.config = config

    def generate(self, report, target) -> str:
        """Build complete HTML report.
        
        Args:
            report: Report object with metadata.
            target: Target object with all scan data.
        
        Returns:
            HTML string.
        """
        summary = target.summary()
        
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>PHANTOM Security Report — {target.domain or target.url or target.root_ip}</title>
<style>
body {{ font-family: 'Consolas', 'Courier New', monospace; background: #0a0a0a; color: #e0e0e0; margin: 0; padding: 20px; }}
.container {{ max-width: 1200px; margin: 0 auto; }}
.header {{ border-bottom: 2px solid #00ff41; padding-bottom: 20px; margin-bottom: 30px; }}
.header h1 {{ color: #00ff41; margin: 0; font-size: 28px; }}
.header .meta {{ color: #888; margin-top: 10px; }}
.section {{ margin: 30px 0; }}
.section h2 {{ color: #00ff41; border-bottom: 1px solid #333; padding-bottom: 8px; }}
.card {{ background: #141414; border: 1px solid #2a2a2a; border-radius: 4px; padding: 15px; margin: 10px 0; }}
.card.critical {{ border-left: 4px solid #ff0044; }}
.card.high {{ border-left: 4px solid #ff6600; }}
.card.medium {{ border-left: 4px solid #ffcc00; }}
.card.low {{ border-left: 4px solid #66ccff; }}
.severity-badge {{ display: inline-block; padding: 2px 8px; border-radius: 3px; font-size: 12px; font-weight: bold; }}
.severity-badge.critical {{ background: #ff0044; color: white; }}
.severity-badge.high {{ background: #ff6600; color: white; }}
.severity-badge.medium {{ background: #ffcc00; color: black; }}
.severity-badge.low {{ background: #66ccff; color: black; }}
table {{ width: 100%; border-collapse: collapse; margin: 10px 0; }}
th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #2a2a2a; }}
th {{ background: #1a1a1a; color: #00ff41; }}
code {{ background: #1a1a1a; padding: 2px 6px; border-radius: 3px; font-size: 13px; color: #ffcc00; word-break: break-all; }}
pre {{ background: #1a1a1a; padding: 15px; border-radius: 4px; overflow-x: auto; font-size: 13px; }}
.timeline-item {{ padding: 5px 0; border-left: 2px solid #333; padding-left: 15px; margin: 5px 0; }}
.timeline-item .time {{ color: #888; font-size: 12px; }}
.timeline-item.success {{ border-left-color: #00ff41; }}
.timeline-item.failed {{ border-left-color: #ff0044; }}
.stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; }}
.stat {{ background: #141414; border: 1px solid #2a2a2a; padding: 20px; text-align: center; border-radius: 4px; }}
.stat .num {{ font-size: 36px; color: #00ff41; font-weight: bold; }}
.stat .label {{ color: #888; font-size: 12px; margin-top: 5px; }}
.footer {{ margin-top: 50px; padding-top: 20px; border-top: 1px solid #333; color: #666; text-align: center; }}
</style>
</head>
<body>
<div class="container">
<div class="header">
    <h1>PHANTOM Security Assessment Report</h1>
    <div class="meta">
        <strong>Target:</strong> {target.domain or target.url or target.root_ip}<br>
        <strong>Generated:</strong> {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}<br>
        <strong>Duration:</strong> {report.duration:.1f}s<br>
        <strong>Severity:</strong> {summary.get('severity_counts', {})}
    </div>
</div>

<div class="section">
    <h2>Executive Summary</h2>
    <div class="stats-grid">
        <div class="stat"><div class="num">{len(target.ips)}</div><div class="label">IPs Found</div></div>
        <div class="stat"><div class="num">{len(target.subdomains)}</div><div class="label">Subdomains</div></div>
        <div class="stat"><div class="num">{len(target.open_ports)}</div><div class="label">Open Ports</div></div>
        <div class="stat"><div class="num">{len(target.tech_stack)}</div><div class="label">Technologies</div></div>
        <div class="stat"><div class="num">{len(target.endpoints)}</div><div class="label">Endpoints</div></div>
        <div class="stat"><div class="num">{len(target.vulnerabilities)}</div><div class="label">Vulnerabilities</div></div>
    </div>
</div>

<div class="section">
    <h2>Reconnaissance Results</h2>
"""
        # DNS Info
        html += "<div class='card'><h3>DNS Records</h3>"
        dns = target.notes.get("dns", {})
        if dns:
            html += "<table><tr><th>Type</th><th>Value</th></tr>"
            for record_type, values in dns.items():
                val_str = ", ".join(str(v) for v in values) if isinstance(values, list) else str(values)
                html += f"<tr><td>{record_type.upper()}</td><td><code>{val_str}</code></td></tr>"
            html += "</table>"
        else:
            html += "<p>No DNS records collected.</p>"
        html += "</div>"
        
        # Open Ports
        html += "<div class='card'><h3>Open Ports</h3>"
        if target.open_ports:
            html += "<table><tr><th>Port</th><th>Service</th><th>Banner</th></tr>"
            for p in target.open_ports:
                html += f"<tr><td>{p.port}/{p.protocol}</td><td>{p.service or '?'}</td><td><code>{p.banner or ''}</code></td></tr>"
            html += "</table>"
        else:
            html += "<p>No open ports discovered.</p>"
        html += "</div>"
        
        # Tech Stack
        html += "<div class='card'><h3>Technology Stack</h3>"
        if target.tech_stack:
            html += "<table><tr><th>Technology</th><th>Version</th></tr>"
            for tech, ver in target.tech_stack.items():
                html += f"<tr><td>{tech}</td><td>{ver}</td></tr>"
            html += "</table>"
        else:
            html += "<p>No technologies identified.</p>"
        html += "</div>"

        html += "</div>"

        # Vulnerabilities
        html += "<div class='section'><h2>Vulnerabilities</h2>"
        if target.vulnerabilities:
            for v in target.vulnerabilities:
                sev = v.severity.lower()
                html += f"""
<div class='card {sev}'>
    <span class='severity-badge {sev}'>{v.severity.upper()}</span>
    <strong>{v.type}</strong>
    <p>{v.description}</p>
    <p><strong>Endpoint:</strong> <code>{v.endpoint}</code></p>
"""
                if v.parameter:
                    html += f"<p><strong>Parameter:</strong> <code>{v.parameter}</code></p>"
                if v.payload:
                    html += f"<p><strong>Payload:</strong> <code>{v.payload}</code></p>"
                if v.poc:
                    html += f"<p><strong>PoC:</strong> <code>{v.poc}</code></p>"
                if v.cve_id:
                    html += f"<p><strong>CVE:</strong> {v.cve_id} (CVSS: {v.cvss_score or 'N/A'})</p>"
                if v.proof:
                    html += f"<pre>{v.proof[:500]}</pre>"
                html += "</div>"
        else:
            html += "<p>No vulnerabilities detected.</p>"

        html += "</div>"

        # Exploit Results
        if target.exploit_results:
            html += "<div class='section'><h2>Exploitation Results</h2>"
            for er in target.exploit_results:
                status = "SUCCESS" if er.success else "FAILED"
                html += f"<div class='card'><h3>{status}</h3>"
                html += f"<p>Type: {er.vulnerability.type}</p>"
                if er.session_id:
                    html += f"<p>Session: <code>{er.session_id}</code></p>"
                if er.shell_type:
                    html += f"<p>Shell: {er.shell_type}</p>"
                if er.output:
                    html += f"<pre>{er.output}</pre>"
                html += "</div>"
            html += "</div>"

        # Timeline
        html += "<div class='section'><h2>Timeline</h2>"
        if target.timeline:
            for entry in target.timeline:
                dur = f" ({entry.duration:.1f}s)" if entry.duration else ""
                html += f"<div class='timeline-item {entry.status}'>"
                html += f"<span class='time'>{entry.timestamp.strftime('%H:%M:%S')}</span> "
                html += f"[{entry.phase.upper()}] {entry.action} — {entry.status.upper()}{dur}"
                html += "</div>"
        else:
            html += "<p>No timeline entries.</p>"
        html += "</div>"

        # Footer
        html += f"""
<div class='footer'>
    <p>Generated by PHANTOM Autonomous Pentest Tool — {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC</p>
    <p>This report contains sensitive security information. Handle with care.</p>
</div>
</div>
</body>
</html>"""
        
        return html

    def save(self, html: str, output_dir: str = "./output") -> str:
        """Write HTML report to file.
        
        Args:
            html: HTML string content.
            output_dir: Output directory path.
        
        Returns:
            Path to saved file.
        """
        os.makedirs(output_dir, exist_ok=True)
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        filename = f"phantom_report_{timestamp}.html"
        path = os.path.join(output_dir, filename)
        
        with open(path, "w") as f:
            f.write(html)
        
        logger.info("Report saved: %s", path)
        return path
