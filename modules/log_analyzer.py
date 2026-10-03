"""
modules/log_analyzer.py
-----------------------
Classifies suspicious HTTP access log requests without claiming exploitation.
"""

import re
from urllib.parse import unquote_plus


LOG_REQUEST_RE = re.compile(r'"(?P<method>GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(?P<path>\S+)\s+HTTP/[^"]+"')


RULES = [
    {
        "attack_type": "DOM-Based XSS / XSS-related suspicious request",
        "severity": "High",
        "patterns": [
            "javascript:",
            "<script",
            "onerror=",
            "onload=",
            "domxssexecutionsink",
            "xsstag",
            "locxss",
        ],
        "description": (
            "The request contains a payload associated with testing for cross-site "
            "scripting behavior. This is a suspicious request / attack attempt, "
            "not proof that XSS executed successfully."
        ),
        "impact": "If the application is vulnerable, attackers may execute script in a user's browser or abuse unsafe DOM sinks.",
        "mitigation": (
            "Validate input; apply context-appropriate output encoding; avoid unsafe "
            "DOM sinks; use a suitable Content Security Policy."
        ),
    },
    {
        "attack_type": "Directory Traversal / Local File Inclusion-style probing",
        "severity": "High",
        "patterns": [
            "../",
            "..\\",
            "%2e%2e%2f",
            "%2f..%2f",
            "/etc/passwd",
            "etc/passwd",
        ],
        "description": (
            "The request attempts to access a file outside the intended directory "
            "using path traversal sequences. This is a suspicious request / attack "
            "attempt, not proof of file disclosure."
        ),
        "impact": "If vulnerable, the application may expose sensitive local files or include unintended server-side resources.",
        "mitigation": (
            "Canonicalize file paths; restrict file access to approved directories; "
            "validate file names; use an allowlist of permitted files/directories; "
            "avoid directly using user-controlled paths."
        ),
    },
    {
        "attack_type": "SQL Injection",
        "severity": "High",
        "patterns": [
            "' or 1=1",
            " or '1'='1",
            "union select",
            " and 1=",
            "and 1=",
            "cast(",
            "sleep(",
            "select ",
            "drop table",
        ],
        "description": (
            "The request contains SQL syntax intended to manipulate a database query. "
            "This is a suspicious request / attack attempt, not proof that SQL "
            "Injection succeeded."
        ),
        "impact": "If vulnerable, attackers may bypass authentication, read data, or modify database contents.",
        "mitigation": (
            "Use parameterized queries; use prepared statements; validate input; "
            "avoid dynamically constructed SQL."
        ),
    },
]


def analyze_logs(log_text: str) -> list[dict]:
    findings = []
    for line_no, line in enumerate((log_text or "").splitlines(), 1):
        line = line.strip()
        if not line:
            continue

        decoded = unquote_plus(line)
        request_path = _extract_request_path(line) or line
        decoded_path = unquote_plus(request_path)
        haystack = decoded.lower()

        for rule in RULES:
            evidence = _first_match(rule["patterns"], haystack, decoded)
            if not evidence:
                continue

            findings.append({
                "type": rule["attack_type"],
                "source": "HTTP Log Analyzer",
                "severity": rule["severity"],
                "url": decoded_path,
                "target": decoded_path,
                "field": f"Log line {line_no}",
                "payload": evidence,
                "evidence": evidence,
                "description": rule["description"],
                "impact": rule["impact"],
                "fix": rule["mitigation"],
                "mitigation": rule["mitigation"],
                "raw_log": line,
            })
            break

    return findings


def _extract_request_path(line: str) -> str | None:
    match = LOG_REQUEST_RE.search(line)
    if not match:
        return None
    return match.group("path")


def _first_match(patterns: list[str], haystack: str, decoded: str) -> str | None:
    raw_lower = haystack
    encoded_lower = decoded.lower()
    for pattern in patterns:
        candidate = pattern.lower()
        if candidate in raw_lower or candidate in encoded_lower:
            return _evidence_snippet(decoded, candidate)
    return None


def _evidence_snippet(text: str, pattern: str) -> str:
    lower = text.lower()
    idx = lower.find(pattern)
    if idx < 0:
        return pattern
    start = max(idx - 45, 0)
    end = min(idx + max(len(pattern), 40) + 45, len(text))
    return text[start:end]
