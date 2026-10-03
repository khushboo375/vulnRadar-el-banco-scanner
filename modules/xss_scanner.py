"""
modules/xss_scanner.py
----------------------
Tests forms for Reflected Cross-Site Scripting (XSS) vulnerabilities.

Strategy: inject a unique XSS payload into each field and check whether
the raw payload appears unescaped in the response body.

FOR EDUCATIONAL USE ONLY — run only against authorised systems.
"""

import requests
import logging
import html

logger = logging.getLogger(__name__)

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    )
}

REQUEST_TIMEOUT = 10

# ---------------------------------------------------------------------------
# XSS payloads — covers common encoding bypasses
# ---------------------------------------------------------------------------
XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg onload=alert('XSS')>",
    "'\"><script>alert('XSS')</script>",
    "<body onload=alert('XSS')>",
    "javascript:alert('XSS')",
    "<iframe src=javascript:alert('XSS')>",
    "<input autofocus onfocus=alert('XSS')>",
]


def test_xss(base_url: str, forms: list[dict]) -> list[dict]:
    """
    Test each text-like field in every form with XSS payloads.
    Returns a list of finding dicts.
    """
    findings = []

    for form in forms:
        action = form["action"]
        method = form["method"]
        inputs = form["inputs"]

        for input_field in inputs:
            field_name = input_field.get("name", "")
            field_type = input_field.get("type", "text")

            if field_type in ("submit", "button", "image", "file", "hidden"):
                continue
            if not field_name:
                continue

            for payload in XSS_PAYLOADS:
                data = _build_form_data(inputs, field_name, payload)

                try:
                    if method == "post":
                        resp = requests.post(action, data=data, headers=HEADERS,
                                             timeout=REQUEST_TIMEOUT, verify=False,
                                             allow_redirects=True)
                    else:
                        resp = requests.get(action, params=data, headers=HEADERS,
                                            timeout=REQUEST_TIMEOUT, verify=False,
                                            allow_redirects=True)

                    finding = _analyse_response(resp, action, field_name, payload)
                    if finding:
                        findings.append(finding)
                        logger.warning(
                            f"[XSS] {action} | field={field_name} | payload={payload}"
                        )
                        break  # One confirmed finding per field is enough

                except requests.RequestException as exc:
                    logger.debug(f"XSS request error ({action}): {exc}")

    return findings


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _build_form_data(inputs: list[dict], target_field: str, payload: str) -> dict:
    """Fill target field with payload; fill others with benign defaults."""
    data = {}
    for inp in inputs:
        name = inp.get("name", "")
        if not name:
            continue
        if name == target_field:
            data[name] = payload
        else:
            itype = inp.get("type", "text")
            if itype == "password":
                data[name] = "password123"
            elif itype == "email":
                data[name] = "test@example.com"
            else:
                data[name] = inp.get("value") or "test"
    return data


def _analyse_response(response, action: str, field: str, payload: str) -> dict | None:
    """
    Check whether the raw (un-HTML-escaped) payload appears in the response.

    If the server properly encodes output, the payload will be escaped and
    therefore harmless. If it appears verbatim → reflected XSS.
    """
    body = response.text

    # The payload must appear literally (not HTML-encoded) to be exploitable
    if payload in body:
        return {
            "type": "Cross-Site Scripting (XSS)",
            "severity": "High",
            "url": action,
            "field": field,
            "payload": payload,
            "evidence": "Payload reflected verbatim in HTTP response body without encoding.",
            "fix": (
                "HTML-encode all user-supplied data before rendering it in the page "
                "(use html.escape() in Python, or a templating engine with auto-escaping "
                "like Jinja2). Implement a strict Content-Security-Policy (CSP) header. "
                "Never insert raw user input into the DOM."
            )
        }

    # Partial match: payload was reflected but partially encoded (still worth flagging)
    escaped = html.escape(payload)
    if escaped != payload and payload[:10] in body:
        return {
            "type": "Potential XSS (Partial Reflection)",
            "severity": "Medium",
            "url": action,
            "field": field,
            "payload": payload,
            "evidence": "Part of the payload was reflected; full encoding may prevent exploitation but should be reviewed.",
            "fix": (
                "Ensure consistent output encoding across all rendering contexts. "
                "Apply a Content-Security-Policy header. Use a framework with built-in XSS protection."
            )
        }

    return None
