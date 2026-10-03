"""
modules/traversal_scanner.py
----------------------------
Tests authorised lab targets for directory traversal indicators.
"""

from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
import logging
import requests

logger = logging.getLogger(__name__)

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    )
}

REQUEST_TIMEOUT = 10

TRAVERSAL_PAYLOADS = [
    "../../../../../../../../etc/passwd",
    "..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
    "..\\..\\..\\..\\windows\\win.ini",
]

SENSITIVE_FILE_SIGNATURES = [
    "root:x:0:0:",
    "[extensions]",
    "[fonts]",
    "daemon:x:",
]

FILE_PARAM_HINTS = ("file", "path", "page", "template", "include", "view", "doc", "folder")


def test_directory_traversal(base_url: str, forms: list[dict]) -> list[dict]:
    findings = []
    seen = set()

    for url, field in _candidate_targets(base_url, forms):
        key = (url, field)
        if key in seen:
            continue
        seen.add(key)

        for payload in TRAVERSAL_PAYLOADS:
            test_url, params = _build_request(url, field, payload)
            try:
                response = requests.get(
                    test_url,
                    params=params,
                    headers=HEADERS,
                    timeout=REQUEST_TIMEOUT,
                    verify=False,
                    allow_redirects=True,
                )
            except requests.RequestException as exc:
                logger.debug("Traversal request error (%s): %s", test_url, exc)
                continue

            finding = _analyse_response(response, test_url, field, payload)
            if finding:
                findings.append(finding)
                logger.warning("[Traversal] %s | field=%s | payload=%s", test_url, field, payload)
                break

    return findings


def _candidate_targets(base_url: str, forms: list[dict]) -> list[tuple[str, str]]:
    candidates = []

    parsed = urlparse(base_url)
    for name, _ in parse_qsl(parsed.query, keep_blank_values=True):
        candidates.append((base_url, name))

    for form in forms:
        action = form.get("action") or base_url
        for input_field in form.get("inputs", []):
            name = input_field.get("name", "")
            field_type = input_field.get("type", "text")
            if not name or field_type in ("submit", "button", "image", "file", "hidden"):
                continue
            if any(hint in name.lower() for hint in FILE_PARAM_HINTS):
                candidates.append((action, name))

    if not candidates:
        candidates.append((base_url, "page"))

    return candidates


def _build_request(url: str, field: str, payload: str) -> tuple[str, dict]:
    parsed = urlparse(url)
    query = dict(parse_qsl(parsed.query, keep_blank_values=True))

    if field in query:
        query[field] = payload
        clean_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, "", parsed.fragment))
        return clean_url, query

    return url, {field: payload}


def _analyse_response(response, url: str, field: str, payload: str) -> dict | None:
    body_lower = response.text.lower()
    for signature in SENSITIVE_FILE_SIGNATURES:
        if signature.lower() in body_lower:
            return {
                "type": "Directory Traversal / Local File Inclusion",
                "source": "Web Scanner",
                "severity": "High",
                "url": url,
                "target": url,
                "field": field,
                "payload": payload,
                "evidence": f"Sensitive file signature detected in response: '{signature}'",
                "description": "Traversal payload returned content that resembles a sensitive local file.",
                "impact": "Attackers may read local files or include unintended resources if user-controlled paths are not constrained.",
                "fix": (
                    "Canonicalize file paths; restrict file access to approved directories; "
                    "validate file names; use allowlists; avoid directly using user-controlled paths."
                ),
                "mitigation": (
                    "Canonicalize file paths; restrict file access to approved directories; "
                    "validate file names; use allowlists; avoid directly using user-controlled paths."
                ),
            }

    if response.status_code == 200 and any(marker in response.url.lower() for marker in ("../", "%2f..", "etc/passwd")):
        return {
            "type": "Potential Directory Traversal",
            "source": "Web Scanner",
            "severity": "Medium",
            "url": url,
            "target": url,
            "field": field,
            "payload": payload,
            "evidence": "Traversal payload was accepted with HTTP 200, but no sensitive file signature was confirmed.",
            "description": "The application accepted a traversal-style path. Manual validation is recommended.",
            "impact": "Improper path handling may expose files if additional controls are missing.",
            "fix": "Normalize paths, reject traversal sequences, and use an allowlist of valid file identifiers.",
            "mitigation": "Normalize paths, reject traversal sequences, and use an allowlist of valid file identifiers.",
        }

    return None
