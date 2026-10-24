"""
Smart Multi-Vulnerability Web Security Scanner
==============================================
Educational tool for use on authorized systems ONLY.
Author: Security Scanner Project
"""

import os
import json
import logging
from datetime import datetime
from flask import Flask, render_template, request, jsonify, send_file
from modules.crawler import create_session, crawl_authenticated_pages, login_to_target
from modules.sql_scanner import test_sql_injection
from modules.xss_scanner import test_xss
from modules.auth_scanner import test_authentication
from modules.traversal_scanner import test_directory_traversal
from modules.network_scanner import run_half_open_scan, run_aggressive_scan, NmapSetupError
from modules.log_analyzer import analyze_logs
from modules.report_generator import generate_html_report

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------
app = Flask(__name__)
os.makedirs("logs", exist_ok=True)
os.makedirs("reports", exist_ok=True)

# Configure logging to file + console
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("logs/scanner.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    """Serve the main dashboard."""
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def scan():
    """
    Main scan endpoint.
    Accepts JSON: { "url": "http://target.com", "username": "", "password": "", "max_pages": 25, "modules": {} }
    Returns streaming-friendly JSON list of findings.
    """
    data = request.get_json() or {}
    target_url = data.get("url", "").strip()

    if not target_url:
        return jsonify({"error": "No URL provided"}), 400

    modules = data.get("modules") or {}
    if not modules:
        modules = {"sqli": True, "xss": True, "auth": True, "traversal": True}

    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    max_pages = data.get("max_pages", 25)
    try:
        max_pages = max(1, min(int(max_pages), 250))
    except (TypeError, ValueError):
        max_pages = 25
    authentication = {"attempted": bool(username or password), "success": False, "message": "Authentication was not requested.", "authenticated_url": None}
    logger.info(
        "Scan request: target=%s username_supplied=%s password_supplied=%s max_pages=%s modules=%s",
        target_url,
        bool(username),
        bool(password),
        max_pages,
        modules,
    )
    findings = []

    try:
        session = create_session()
        if username or password:
            logger.info("Authentication attempted: yes")
            if not username or not password:
                authentication.update(message="Both username and password are required to attempt authentication.")
            else:
                authentication = login_to_target(session, target_url, username, password)
                authentication["attempted"] = True
            if not authentication["success"]:
                logger.warning("Authentication result: failed; authenticated crawl was not performed")
                return jsonify({
                    "error": "Authentication failed — authenticated scan was not performed.",
                    "authentication": authentication,
                }), 401
            logger.info("Authentication result: success")
            crawl_start_url = authentication["final_url"]
        else:
            logger.info("Authentication attempted: no")
            crawl_start_url = target_url

        crawl_session = session
        logger.info("Crawling %s pages with the %s session", "authenticated" if authentication["success"] else "target", "authenticated" if authentication["success"] else "new")
        crawl = crawl_authenticated_pages(crawl_session, crawl_start_url, max_pages=max_pages)
        forms = crawl["forms"]
        logger.info(
            "%s crawl page count: %s; form count: %s",
            "Authenticated" if authentication["success"] else "Unauthenticated",
            crawl["pages_discovered"],
            crawl["forms_discovered"],
        )

        # Step 2: SQL Injection tests
        if modules.get("sqli", modules.get("sql", True)):
            logger.info("Testing SQL Injection...")
            findings.extend(test_sql_injection(target_url, forms, session=crawl_session))

        # Step 3: XSS tests
        if modules.get("xss", True):
            logger.info("Testing XSS...")
            findings.extend(test_xss(target_url, forms, session=crawl_session))

        # Step 4: Authentication tests
        if modules.get("auth", True):
            logger.info("Testing Authentication...")
            findings.extend(test_authentication(target_url, forms))

        # Step 5: Directory Traversal tests
        if modules.get("traversal", True):
            logger.info("Testing Directory Traversal...")
            findings.extend(test_directory_traversal(target_url, forms, session=crawl_session))

    except Exception as exc:
        logger.error(f"Scan error: {exc}")
        return jsonify({"error": str(exc)}), 500

    findings = normalize_findings(findings, default_source="Web Scanner")
    logger.info(f"Scan complete — {len(findings)} finding(s)")

    # Persist latest report for download
    report_path = f"reports/report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    report_context = {
        "title": "EL BANCO PENETRATION TEST REPORT",
        "target_url": target_url,
        "web_findings": findings,
        "authentication": authentication,
        "crawl": crawl,
        "modules": modules,
    }
    generate_html_report(target_url, findings, report_path, report_context=report_context)

    return jsonify({
        "url": target_url,
        "total": len(findings),
        "findings": findings,
        "authentication": authentication,
        "crawl": {
            "pages_discovered": crawl["pages_discovered"],
            "forms_discovered": crawl["forms_discovered"],
        },
        "modules": modules,
        "report": report_path
    })


@app.route("/network-scan", methods=["POST"])
def network_scan():
    """Run authorised Nmap reconnaissance."""
    data = request.get_json() or {}
    target = data.get("target", "").strip()
    scan_type = data.get("scan_type", "").strip()

    if scan_type not in {"half_open", "aggressive"}:
        return jsonify({"error": "Select either Half-Open Scan or Aggressive Scan."}), 400

    try:
        if scan_type == "half_open":
            result = run_half_open_scan(target)
        else:
            result = run_aggressive_scan(target)
    except (ValueError, NmapSetupError, RuntimeError) as exc:
        logger.error("Network scan error: %s", exc)
        return jsonify({"error": str(exc)}), 400

    report_path = f"reports/report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    generate_html_report(
        target,
        result.get("findings", []),
        report_path,
        report_context={
            "title": "EL BANCO PENETRATION TEST REPORT",
            "network_results": result,
        },
    )

    return jsonify({
        "target": target,
        "scan_type": scan_type,
        "result": result,
        "findings": result.get("findings", []),
        "report": report_path,
    })


@app.route("/analyze-logs", methods=["POST"])
def analyze_http_logs():
    """Analyze pasted or uploaded HTTP access logs."""
    log_text = ""
    if request.files.get("log_file"):
        log_text = request.files["log_file"].read().decode("utf-8", errors="replace")
    else:
        data = request.get_json(silent=True) or {}
        log_text = data.get("log_text", "")

    if not log_text.strip():
        return jsonify({"error": "Paste log text or upload an HTTP access log file."}), 400

    findings = analyze_logs(log_text)
    logger.info("HTTP log analysis complete — %s finding(s)", len(findings))

    report_path = f"reports/report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    generate_html_report(
        "HTTP Access Logs",
        findings,
        report_path,
        report_context={
            "title": "EL BANCO PENETRATION TEST REPORT",
            "log_findings": findings,
        },
    )

    return jsonify({
        "target": "HTTP Access Logs",
        "total": len(findings),
        "findings": findings,
        "report": report_path,
    })


@app.route("/download-report")
def download_report():
    """Download the most recently generated HTML report."""
    reports_dir = "reports"
    files = sorted(
        [f for f in os.listdir(reports_dir) if f.endswith(".html")],
        reverse=True
    )
    if not files:
        return jsonify({"error": "No report available yet"}), 404

    latest = os.path.join(reports_dir, files[0])
    return send_file(latest, as_attachment=True, download_name="security_report.html")


def normalize_findings(findings: list[dict], default_source: str) -> list[dict]:
    """Ensure every scanner returns the unified finding fields."""
    normalized = []
    for finding in findings:
        item = dict(finding)
        item.setdefault("source", default_source)
        item.setdefault("target", item.get("url", ""))
        item.setdefault("description", _default_description(item.get("type", "Finding")))
        item.setdefault("impact", _default_impact(item.get("type", "Finding")))
        item.setdefault("mitigation", item.get("fix", "Review the finding and apply the recommended security control."))
        item.setdefault("fix", item.get("mitigation", "Review the finding and apply the recommended security control."))
        normalized.append(item)
    return normalized


def _default_description(finding_type: str) -> str:
    if "SQL" in finding_type:
        return "The scanner observed behavior associated with SQL Injection testing."
    if "XSS" in finding_type or "Cross-Site" in finding_type:
        return "The scanner observed behavior associated with reflected cross-site scripting."
    if "Auth" in finding_type or "Credential" in finding_type or "Password" in finding_type:
        return "The scanner observed an authentication or account protection weakness."
    return "The scanner observed a security-relevant condition that should be reviewed."


def _default_impact(finding_type: str) -> str:
    if "SQL" in finding_type:
        return "Potential unauthorized database access if the application is vulnerable."
    if "XSS" in finding_type or "Cross-Site" in finding_type:
        return "Potential browser-side script execution if output is not safely encoded."
    if "Auth" in finding_type or "Credential" in finding_type or "Password" in finding_type:
        return "Potential account compromise, user enumeration, or brute-force exposure."
    return "Potential increase in application risk depending on exploitability and exposure."


# ---------------------------------------------------------------------------
if __name__ == "__main__":
    app.run(debug=True, port=5000)
