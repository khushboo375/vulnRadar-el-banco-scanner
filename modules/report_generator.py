"""
modules/report_generator.py
---------------------------
Generates a self-contained HTML security report from scan findings.
"""

from datetime import datetime

SEVERITY_COLOR = {
    "High":   "#ef4444",
    "Medium": "#f59e0b",
    "Low":    "#22c55e",
    "Info":   "#38bdf8",
}

SEVERITY_BG = {
    "High":   "#fef2f2",
    "Medium": "#fffbeb",
    "Low":    "#f0fdf4",
    "Info":   "#eff6ff",
}


def generate_html_report(target_url: str, findings: list[dict], output_path: str, report_context: dict | None = None) -> str:
    """
    Write a polished, self-contained HTML report to output_path.
    Returns the path.
    """
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    report_context = report_context or {}
    title = report_context.get("title", "EL BANCO PENETRATION TEST REPORT")
    all_findings = findings or []
    high   = sum(1 for f in all_findings if f.get("severity") == "High")
    medium = sum(1 for f in all_findings if f.get("severity") == "Medium")
    low    = sum(1 for f in all_findings if f.get("severity") == "Low")
    info   = sum(1 for f in all_findings if f.get("severity") == "Info")

    cards_html = ""
    for i, f in enumerate(all_findings, 1):
        severity = f.get("severity", "Info")
        color  = SEVERITY_COLOR.get(severity, "#6b7280")
        bg     = SEVERITY_BG.get(severity,    "#f9fafb")
        mitigation = f.get("mitigation") or f.get("fix", "")
        cards_html += f"""
        <div class="finding-card" style="border-left: 4px solid {color}; background:{bg};">
            <div class="finding-header">
                <span class="finding-num">#{i}</span>
                <span class="finding-type">{_esc(f.get('type', 'Finding'))}</span>
                <span class="severity-badge" style="background:{color};">{_esc(severity)}</span>
            </div>
            <table class="finding-table">
                <tr><th>Source</th><td>{_esc(f.get('source', 'Web Scanner'))}</td></tr>
                <tr><th>Target</th><td>{_esc(f.get('target') or f.get('url') or target_url)}</td></tr>
                <tr><th>URL / Endpoint</th><td>{_esc(f.get('url', ''))}</td></tr>
                <tr><th>HTTP Method</th><td>{_esc(f.get('method', ''))}</td></tr>
                <tr><th>Affected Field</th><td>{_esc(str(f.get('field','')))}</td></tr>
                <tr><th>Test Payload</th><td><code>{_esc(str(f.get('payload','')))}</code></td></tr>
                <tr><th>Description</th><td>{_esc(f.get('description',''))}</td></tr>
                <tr><th>Impact</th><td>{_esc(f.get('impact',''))}</td></tr>
                <tr><th>Evidence</th><td>{_esc(f.get('evidence',''))}</td></tr>
                <tr><th>Mitigation</th><td class="fix-cell">{_esc(mitigation)}</td></tr>
            </table>
        </div>
        """

    if not all_findings:
        cards_html = '<p class="no-findings">No vulnerabilities detected during this scan.</p>'

    network_html = _render_network_section(report_context.get("network_results"))
    web_html = _render_finding_section("4. Web Application Findings", report_context.get("web_findings", []))
    log_html = _render_finding_section("5. HTTP Log Analysis", report_context.get("log_findings", []))
    mitigation_html = _render_mitigations(all_findings)

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>{_esc(title)} — {_esc(target_url)}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Segoe UI', system-ui, sans-serif; background:#0f172a; color:#e2e8f0; }}
  header {{ background: linear-gradient(135deg,#1e3a5f,#0f172a); padding: 2.5rem 3rem; border-bottom: 1px solid #1e40af; }}
  header h1 {{ font-size: 1.8rem; color:#60a5fa; letter-spacing:.05em; }}
  header p  {{ color:#94a3b8; margin-top:.4rem; font-size:.95rem; }}
  .disclaimer {{ background:#1e293b; border:1px solid #ef4444; color:#fca5a5;
                  margin:2rem 3rem; padding:1rem 1.5rem; border-radius:8px; font-size:.875rem; }}
  .stats {{ display:flex; gap:1.5rem; margin:2rem 3rem; flex-wrap:wrap; }}
  .stat-card {{ background:#1e293b; border-radius:10px; padding:1.2rem 2rem; flex:1; min-width:140px; text-align:center; border:1px solid #334155; }}
  .stat-card .num {{ font-size:2rem; font-weight:700; }}
  .stat-card .label {{ font-size:.8rem; color:#94a3b8; margin-top:.3rem; text-transform:uppercase; letter-spacing:.08em; }}
  .stat-card.high   .num {{ color:#ef4444; }}
  .stat-card.medium .num {{ color:#f59e0b; }}
  .stat-card.low    .num {{ color:#22c55e; }}
  .stat-card.total  .num {{ color:#60a5fa; }}
  .findings {{ margin: 0 3rem 3rem; }}
  .findings h2 {{ font-size:1.2rem; color:#94a3b8; margin-bottom:1.5rem; border-bottom:1px solid #334155; padding-bottom:.7rem; }}
  .report-section {{ margin: 0 3rem 2rem; background:#111827; border:1px solid #243244; border-radius:8px; padding:1.2rem; }}
  .report-section h2 {{ font-size:1.05rem; color:#93c5fd; margin-bottom:.8rem; }}
  .report-section p, .report-section li {{ color:#cbd5e1; font-size:.9rem; line-height:1.6; }}
  .report-section ul {{ margin-left:1.2rem; }}
  .simple-table {{ width:100%; border-collapse:collapse; font-size:.85rem; margin-top:.6rem; }}
  .simple-table th, .simple-table td {{ border-bottom:1px solid #243244; padding:.45rem; text-align:left; color:#cbd5e1; vertical-align:top; }}
  .simple-table th {{ color:#93c5fd; }}
  .finding-card {{ border-radius:10px; padding:1.5rem; margin-bottom:1.5rem; }}
  .finding-header {{ display:flex; align-items:center; gap:.8rem; margin-bottom:1rem; flex-wrap:wrap; }}
  .finding-num {{ color:#64748b; font-size:.85rem; font-weight:600; }}
  .finding-type {{ font-size:1.05rem; font-weight:700; color:#1e293b; flex:1; }}
  .severity-badge {{ padding:.2rem .8rem; border-radius:999px; color:#fff; font-size:.75rem; font-weight:700; text-transform:uppercase; letter-spacing:.05em; }}
  .finding-table {{ width:100%; border-collapse:collapse; font-size:.875rem; }}
  .finding-table th {{ width:160px; text-align:left; color:#4b5563; font-weight:600; padding:.5rem .5rem .5rem 0; vertical-align:top; white-space:nowrap; }}
  .finding-table td {{ color:#1e293b; padding:.5rem; word-break:break-all; }}
  .finding-table .fix-cell {{ color:#166534; font-weight:500; }}
  code {{ background:rgba(0,0,0,.08); padding:.1em .4em; border-radius:4px; font-family:monospace; font-size:.85em; }}
  .no-findings {{ text-align:center; padding:3rem; color:#22c55e; font-size:1.2rem; }}
  footer {{ text-align:center; padding:2rem; color:#475569; font-size:.8rem; border-top:1px solid #1e293b; }}
</style>
</head>
<body>
<header>
  <h1>{_esc(title)}</h1>
  <p><strong>Target:</strong> {_esc(target_url)}&nbsp;&nbsp;|&nbsp;&nbsp;<strong>Scanned:</strong> {now}</p>
</header>

<div class="disclaimer">
  <strong>EDUCATIONAL USE ONLY.</strong> This report was generated by an automated security
  scanner for authorised testing on intentionally vulnerable applications. Do NOT use this tool
  against systems you do not own or have explicit written permission to test.
</div>

<div class="stats">
  <div class="stat-card total"><div class="num">{len(all_findings)}</div><div class="label">Total Findings</div></div>
  <div class="stat-card high"><div class="num">{high}</div><div class="label">High Severity</div></div>
  <div class="stat-card medium"><div class="num">{medium}</div><div class="label">Medium Severity</div></div>
  <div class="stat-card low"><div class="num">{low}</div><div class="label">Low Severity</div></div>
</div>

<div class="report-section">
  <h2>1. Executive Summary</h2>
  <p>VulnRadar assessed the authorised target using the enabled reconnaissance, web application testing, and HTTP log analysis workflows. Findings are evidence-based and identify suspicious attempts separately from confirmed vulnerabilities.</p>
</div>

<div class="report-section">
  <h2>2. Target Information</h2>
  <p><strong>Primary target:</strong> {_esc(target_url)}</p>
  <p><strong>Assessment scope:</strong> Localhost, Docker lab environments, intentionally vulnerable applications, and systems with explicit authorization.</p>
</div>

{network_html}
{_render_scan_metadata(report_context)}
{web_html}
{log_html}

<div class="findings">
  <h2>6. Evidence</h2>
  {cards_html}
</div>

<div class="report-section">
  <h2>7. Severity Summary</h2>
  <p>High: {high} | Medium: {medium} | Low: {low} | Info: {info}</p>
</div>

<div class="report-section">
  <h2>8. Recommended Mitigations</h2>
  {mitigation_html}
</div>

<footer>Generated by Smart Multi-Vulnerability Web Security Scanner &nbsp;·&nbsp; {now}</footer>
</body>
</html>"""

    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(html)

    return output_path


def _esc(text: str) -> str:
    """HTML-escape a string for safe insertion into the report."""
    return (str(text or "")
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;"))


def _render_network_section(network_results: dict | None) -> str:
    if not network_results:
        return '<div class="report-section"><h2>3. Network Reconnaissance</h2><p>No network reconnaissance results were included in this report.</p></div>'

    rows = ""
    for host in network_results.get("hosts", []):
        for port in host.get("ports", []):
            version = " ".join(bit for bit in [port.get("product"), port.get("version"), port.get("extra")] if bit)
            rows += (
                "<tr>"
                f"<td>{_esc(host.get('host'))}</td>"
                f"<td>{_esc(host.get('state'))}</td>"
                f"<td>{_esc(str(port.get('port')) + '/' + port.get('protocol', 'tcp'))}</td>"
                f"<td>{_esc(port.get('state'))}</td>"
                f"<td>{_esc(port.get('service'))}</td>"
                f"<td>{_esc(version)}</td>"
                "</tr>"
            )

    os_rows = ""
    for host in network_results.get("hosts", []):
        for os_match in host.get("os_matches", []):
            os_rows += f"<li>{_esc(host.get('host'))}: {_esc(os_match.get('name'))} ({_esc(os_match.get('accuracy'))}% accuracy)</li>"

    trace_rows = ""
    for host in network_results.get("hosts", []):
        for hop in host.get("traceroute", []):
            trace_rows += f"<li>TTL {_esc(hop.get('ttl'))}: {_esc(hop.get('ipaddr'))} {_esc(hop.get('host'))} RTT {_esc(hop.get('rtt'))}</li>"

    script_rows = ""
    for host in network_results.get("hosts", []):
        for script_group in host.get("scripts", []):
            script_rows += f"<li>{_esc(host.get('host'))} { _esc(script_group.get('port'))}: {_esc(script_group.get('scripts'))}</li>"

    return f"""
    <div class="report-section">
      <h2>3. Network Reconnaissance</h2>
      <p><strong>Scan:</strong> {_esc(network_results.get('scan_type'))}</p>
      <p><strong>Command:</strong> <code>{_esc(network_results.get('command'))}</code></p>
      <table class="simple-table">
        <tr><th>Host</th><th>Host State</th><th>Port</th><th>Port State</th><th>Service</th><th>Version</th></tr>
        {rows or '<tr><td colspan="6">No port results returned.</td></tr>'}
      </table>
      <p><strong>OS Detection:</strong></p><ul>{os_rows or '<li>No OS match returned.</li>'}</ul>
      <p><strong>NSE / Script Results:</strong></p><ul>{script_rows or '<li>No script output returned.</li>'}</ul>
      <p><strong>Traceroute:</strong></p><ul>{trace_rows or '<li>No traceroute output returned.</li>'}</ul>
    </div>
    """


def _render_scan_metadata(report_context: dict) -> str:
    """Render web authentication/crawl metadata without secrets."""
    auth = report_context.get("authentication") or {}
    crawl = report_context.get("crawl") or {}
    modules = report_context.get("modules") or {}
    attempted = "Yes" if auth.get("attempted") else "No"
    success = "Yes" if auth.get("success") else "No"
    enabled = ", ".join(name for name, enabled in modules.items() if enabled) or "None"
    return f"""
    <div class="report-section">
      <h2>3. Scan Metadata</h2>
      <table class="simple-table">
        <tr><th>Authentication attempted</th><td>{attempted}</td></tr>
        <tr><th>Authentication successful</th><td>{success}</td></tr>
        <tr><th>Authentication status</th><td>{_esc(auth.get('message', ''))}</td></tr>
        <tr><th>Pages discovered</th><td>{_esc(crawl.get('pages_discovered', 0))}</td></tr>
        <tr><th>Forms discovered</th><td>{_esc(crawl.get('forms_discovered', 0))}</td></tr>
        <tr><th>Modules executed</th><td>{_esc(enabled)}</td></tr>
      </table>
    </div>
    """


def _render_finding_section(title: str, section_findings: list[dict]) -> str:
    if not section_findings:
        return f'<div class="report-section"><h2>{_esc(title)}</h2><p>No findings were included for this section.</p></div>'

    items = "".join(
        f"<li><strong>{_esc(f.get('type'))}</strong> ({_esc(f.get('severity'))}) - {_esc(f.get('evidence'))}</li>"
        for f in section_findings
    )
    return f'<div class="report-section"><h2>{_esc(title)}</h2><ul>{items}</ul></div>'


def _render_mitigations(findings: list[dict]) -> str:
    mitigations = []
    for finding in findings:
        mitigation = finding.get("mitigation") or finding.get("fix")
        if mitigation and mitigation not in mitigations:
            mitigations.append(mitigation)
    if not mitigations:
        return "<p>No specific mitigations were generated.</p>"
    return "<ul>" + "".join(f"<li>{_esc(item)}</li>" for item in mitigations) + "</ul>"
