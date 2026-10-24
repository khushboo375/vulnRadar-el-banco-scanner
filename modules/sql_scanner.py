"""
modules/sql_scanner.py
----------------------
Tests forms for SQL Injection vulnerabilities by injecting common payloads
and analysing the HTTP response for database error signatures.

FOR EDUCATIONAL USE ONLY — run only against systems you own or have
explicit written permission to test.
"""

import requests
from bs4 import BeautifulSoup
import logging

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
# SQLi payloads — classic injections used in educational labs
# ---------------------------------------------------------------------------
SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1 --",
    "' OR 1=1 #",
    "\" OR \"1\"=\"1",
    "admin'--",
    "' OR 'x'='x",
    "1' ORDER BY 1--",
    "1 UNION SELECT NULL--",
]

# Strings that appear in database error messages — a strong signal of SQLi
DB_ERROR_SIGNATURES = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "sqlstate",
    "odbc microsoft access driver",
    "ora-00933",          # Oracle
    "pg::syntaxerror",    # PostgreSQL
    "sqlite3::exception", # SQLite
    "microsoft ole db provider for sql server",
    "syntax error",
    "sql error",
    "database error",
    "invalid query",
    "mysql_fetch",
    "num_rows",
]

# Strings that appear when a SQLi causes data to leak or bypass auth
SUCCESS_INDICATORS = [
    "welcome",
    "admin",
    "dashboard",
    "logout",
    "profile",
    "logged in",
    "successfully",
]


def test_sql_injection(base_url: str, forms: list[dict], session=None) -> list[dict]:
    """
    Iterate over all crawled forms and test each text-like field with SQLi payloads.

    Returns a list of finding dicts (compatible with the frontend display format).
    """
    findings = []

    for form in forms:
        action  = form["action"]
        method  = form["method"]
        inputs  = form["inputs"]

        for input_field in inputs:
            field_name = input_field.get("name", "")
            field_type = input_field.get("type", "text")

            # Only inject into text-like fields
            if field_type in ("submit", "button", "image", "file", "hidden"):
                continue
            if not field_name:
                continue

            for payload in SQLI_PAYLOADS:
                # Build a data dict: fill the target field with payload,
                # fill others with benign defaults
                data = _build_form_data(inputs, field_name, payload)

                try:
                    client = session or requests
                    if method == "post":
                        resp = client.post(action, data=data, headers=HEADERS,
                                           timeout=REQUEST_TIMEOUT, verify=False,
                                           allow_redirects=True)
                    else:
                        resp = client.get(action, params=data, headers=HEADERS,
                                          timeout=REQUEST_TIMEOUT, verify=False,
                                          allow_redirects=True)

                    finding = _analyse_response(resp, action, field_name, payload)
                    if finding:
                        finding["method"] = method.upper()
                        findings.append(finding)
                        logger.warning("[SQLi] %s | field=%s", action, field_name)
                        # Don't spam with multiple payloads once we found it
                        break

                except requests.RequestException as exc:
                    logger.debug(f"SQLi request error ({action}): {exc}")

    return findings


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _build_form_data(inputs: list[dict], target_field: str, payload: str) -> dict:
    """
    Build a POST/GET data dictionary.
    Inject the payload into target_field; use innocuous defaults for others.
    """
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
            elif itype == "number":
                data[name] = "1"
            else:
                data[name] = inp.get("value") or "test"
    return data


def _analyse_response(response, action: str, field: str, payload: str) -> dict | None:
    """
    Inspect the response body for DB error strings or auth-bypass indicators.
    Return a finding dict if vulnerable, else None.
    """
    body_lower = response.text.lower()

    # Check for database errors (high confidence)
    for sig in DB_ERROR_SIGNATURES:
        if sig in body_lower:
            return {
                "type": "SQL Injection",
                "severity": "High",
                "url": action,
                "field": field,
                "payload": payload,
                "evidence": f"Database error signature detected: '{sig}'",
                "fix": (
                    "Use parameterised queries / prepared statements. "
                    "Never concatenate user input into SQL strings. "
                    "Apply an ORM (e.g. SQLAlchemy) and validate/sanitise all inputs."
                )
            }

    return None
