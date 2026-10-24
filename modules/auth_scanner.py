"""
modules/auth_scanner.py
-----------------------
Tests login forms for weak authentication weaknesses:
  1. Brute-force simulation with common credential pairs
  2. Missing rate-limiting detection
  3. Weak password policy analysis
  4. Verbose error messages that reveal whether a username exists

FOR EDUCATIONAL USE ONLY — run only against authorised systems.
"""

import requests
import time
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
# Weak credential pairs — the ones attackers try first
# ---------------------------------------------------------------------------
WEAK_CREDENTIALS = [
    ("admin",  "admin"),
    ("admin",  "password"),
    ("admin",  "123456"),
    ("admin",  "admin123"),
    ("admin",  "password123"),
    ("root",   "root"),
    ("root",   "toor"),
    ("user",   "user"),
    ("user",   "password"),
    ("test",   "test"),
    ("guest",  "guest"),
    ("admin",  ""),          # blank password
    ("",       "admin"),     # blank username
]

# Keywords that suggest a login form
LOGIN_KEYWORDS = [
    "login", "log in", "signin", "sign in", "username", "email",
    "password", "passwd", "pwd", "authenticate"
]

# Indicators of successful login in a response
SUCCESS_INDICATORS = [
    "logout", "log out", "sign out", "welcome", "dashboard",
    "profile", "my account", "logged in", "session"
]

# Patterns that indicate verbose (user-enumeration) errors
ENUMERATION_PATTERNS = [
    "invalid username",
    "user not found",
    "no account",
    "incorrect username",
    "email not found",
    "username does not exist",
]


def test_authentication(base_url: str, forms: list[dict]) -> list[dict]:
    """
    Find login forms and test them for authentication weaknesses.
    Returns a list of finding dicts.
    """
    findings = []

    auth_session = requests.Session()
    auth_session.headers.update(HEADERS)
    login_forms = _identify_login_forms(forms)
    logger.info(f"Found {len(login_forms)} login form(s) to test.")

    for form in login_forms:
        action  = form["action"]
        inputs  = form["inputs"]

        # --- Test 1: Weak credentials ---
        weak_finding = _test_weak_credentials(action, inputs, auth_session)
        if weak_finding:
            findings.append(weak_finding)

        # --- Test 2: Rate limiting detection ---
        rate_finding = _test_rate_limiting(action, inputs, auth_session)
        if rate_finding:
            findings.append(rate_finding)

        # --- Test 3: User enumeration via verbose errors ---
        enum_finding = _test_user_enumeration(action, inputs, auth_session)
        if enum_finding:
            findings.append(enum_finding)

        # --- Test 4: Password strength policy ---
        policy_finding = _test_password_policy(action, inputs, auth_session)
        if policy_finding:
            findings.append(policy_finding)

    return findings


# ---------------------------------------------------------------------------
# Individual test functions
# ---------------------------------------------------------------------------

def _test_weak_credentials(action: str, inputs: list[dict], session=None) -> dict | None:
    """Try common username/password pairs and detect successful login."""
    user_field, pass_field = _find_credential_fields(inputs)
    if not user_field or not pass_field:
        return None

    for username, password in WEAK_CREDENTIALS:
        data = _build_login_data(inputs, user_field, pass_field, username, password)
        try:
            resp = (session or requests).post(action, data=data, headers=HEADERS,
                                 timeout=REQUEST_TIMEOUT, verify=False,
                                 allow_redirects=True)
            body_lower = resp.text.lower()

            if any(ind in body_lower for ind in SUCCESS_INDICATORS):
                logger.warning("[Auth] Common credentials succeeded at %s for username=%s", action, username)
                return {
                    "type": "Weak Authentication — Default Credentials",
                    "severity": "High",
                    "url": action,
                    "field": f"{user_field} / {pass_field}",
                    "payload": f"Common credential pair for username '{username}' (password redacted)",
                    "evidence": (
                        f"Login succeeded with a common credential pair for username '{username}'. The password is redacted."
                    ),
                    "fix": (
                        "Enforce a strong password policy (min 12 chars, mixed case, "
                        "numbers, symbols). Remove all default credentials. "
                        "Require password change on first login. "
                        "Use multi-factor authentication (MFA)."
                    )
                }
        except requests.RequestException as exc:
            logger.debug(f"Auth request error: {exc}")

    return None


def _test_rate_limiting(action: str, inputs: list[dict], session=None) -> dict | None:
    """
    Send 10 rapid login attempts and check whether the server ever blocks us.
    If all 10 requests return HTTP 200, rate limiting is likely absent.
    """
    user_field, pass_field = _find_credential_fields(inputs)
    if not user_field or not pass_field:
        return None

    blocked = False
    attempts = 10

    for i in range(attempts):
        data = _build_login_data(
            inputs, user_field, pass_field,
            "testuser", f"wrongpass{i}"
        )
        try:
            resp = (session or requests).post(action, data=data, headers=HEADERS,
                                 timeout=REQUEST_TIMEOUT, verify=False,
                                 allow_redirects=False)
            # 429 Too Many Requests or a redirect to a lockout page = rate limited
            if resp.status_code == 429 or "locked" in resp.text.lower():
                blocked = True
                break
        except requests.RequestException:
            pass
        time.sleep(0.1)  # slight delay to be polite even in testing

    if not blocked:
        logger.warning(f"[Auth] No rate limiting detected on {action}")
        return {
            "type": "Missing Rate Limiting on Login",
            "severity": "Medium",
            "url": action,
            "field": f"{user_field} / {pass_field}",
            "payload": f"{attempts} rapid login attempts",
            "evidence": (
                f"Server accepted {attempts} consecutive failed login requests "
                "without throttling, CAPTCHA, or account lockout."
            ),
            "fix": (
                "Implement account lockout after 5–10 failed attempts. "
                "Add exponential back-off or CAPTCHA. "
                "Use IP-based rate limiting (e.g. Flask-Limiter or a WAF). "
                "Log and alert on repeated failures."
            )
        }

    return None


def _test_user_enumeration(action: str, inputs: list[dict], session=None) -> dict | None:
    """
    Detect if the application reveals whether a username exists through
    different error messages for 'unknown user' vs 'wrong password'.
    """
    user_field, pass_field = _find_credential_fields(inputs)
    if not user_field or not pass_field:
        return None

    # Request 1: definitely non-existent user
    data_no_user = _build_login_data(inputs, user_field, pass_field,
                                     "xXx_nonexistent_xXx_99999", "wrongpassword")
    # Request 2: a common username that might exist
    data_common  = _build_login_data(inputs, user_field, pass_field,
                                     "admin", "wrongpassword")

    try:
        client = session or requests
        resp1 = client.post(action, data=data_no_user, headers=HEADERS,
                               timeout=REQUEST_TIMEOUT, verify=False)
        resp2 = client.post(action, data=data_common, headers=HEADERS,
                               timeout=REQUEST_TIMEOUT, verify=False)

        body1 = resp1.text.lower()
        body2 = resp2.text.lower()

        # Check for explicit user-enumeration messages in either response
        for pattern in ENUMERATION_PATTERNS:
            if pattern in body1 or pattern in body2:
                return {
                    "type": "User Enumeration via Verbose Errors",
                    "severity": "Medium",
                    "url": action,
                    "field": user_field,
                    "payload": "xXx_nonexistent_xXx_99999 / admin",
                    "evidence": (
                        f"Application reveals whether a username exists. "
                        f"Pattern found: '{pattern}'"
                    ),
                    "fix": (
                        "Return a generic error for all failed logins: "
                        "'Invalid username or password'. "
                        "Never reveal which part of the credential was wrong."
                    )
                }

        # If response bodies differ significantly, that too leaks user existence
        if len(body1) != len(body2) and abs(len(body1) - len(body2)) > 50:
            if body1 != body2:
                return {
                    "type": "User Enumeration via Response Differences",
                    "severity": "Low",
                    "url": action,
                    "field": user_field,
                    "payload": "Response body analysis",
                    "evidence": (
                        "Different response lengths/content for existing vs non-existing usernames "
                        f"({len(body2)} vs {len(body1)} chars) may allow username enumeration."
                    ),
                    "fix": (
                        "Normalise all failed-login responses to the same content and length. "
                        "Add a constant-time comparison to prevent timing attacks."
                    )
                }

    except requests.RequestException as exc:
        logger.debug(f"User enum request error: {exc}")

    return None


def _test_password_policy(action: str, inputs: list[dict], session=None) -> dict | None:
    """
    Try to register / log in with a trivially weak password to see if the
    server rejects it. If not → likely no password policy enforced.
    """
    user_field, pass_field = _find_credential_fields(inputs)
    if not user_field or not pass_field:
        return None

    weak_passwords = ["1", "12", "123", "abc", "pass"]

    for pwd in weak_passwords:
        data = _build_login_data(inputs, user_field, pass_field, "testuser", pwd)
        try:
            resp = (session or requests).post(action, data=data, headers=HEADERS,
                                 timeout=REQUEST_TIMEOUT, verify=False,
                                 allow_redirects=True)
            body_lower = resp.text.lower()

            # If server doesn't reject the weak password attempt explicitly
            rejected_terms = ["too short", "minimum", "must be at least",
                              "password strength", "not strong enough"]
            if not any(t in body_lower for t in rejected_terms):
                return {
                    "type": "No Password Strength Policy",
                    "severity": "Medium",
                    "url": action,
                    "field": pass_field,
                    "payload": f"Weak password length test (length={len(pwd)}; value redacted)",
                    "evidence": (
                        f"Server accepted a {len(pwd)}-character password without complaint. "
                        "No minimum length or complexity requirement appears to be enforced."
                    ),
                    "fix": (
                        "Enforce a minimum password length of 12 characters. "
                        "Require a mix of uppercase, lowercase, digits, and symbols. "
                        "Check passwords against breach databases (e.g. HaveIBeenPwned API). "
                        "Display a real-time password strength meter to users."
                    )
                }
        except requests.RequestException:
            pass

    return None


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def _identify_login_forms(forms: list[dict]) -> list[dict]:
    """
    Return forms that look like login forms (contain a password field
    or keywords in their input names).
    """
    login_forms = []
    for form in forms:
        has_password = any(
            inp.get("type") == "password" for inp in form["inputs"]
        )
        has_keyword = any(
            any(kw in (inp.get("name") or "").lower() for kw in LOGIN_KEYWORDS)
            for inp in form["inputs"]
        )
        if has_password or has_keyword:
            login_forms.append(form)
    return login_forms


def _find_credential_fields(inputs: list[dict]) -> tuple[str | None, str | None]:
    """Return (username_field_name, password_field_name) from a form's inputs."""
    user_field = None
    pass_field = None

    for inp in inputs:
        name  = (inp.get("name") or "").lower()
        itype = inp.get("type", "text")

        if itype == "password":
            pass_field = inp["name"]
        elif itype in ("text", "email") and not user_field:
            user_field = inp["name"]

    return user_field, pass_field


def _build_login_data(inputs: list[dict], user_field: str, pass_field: str,
                      username: str, password: str) -> dict:
    """Build form data dict with username and password injected."""
    data = {}
    for inp in inputs:
        name = inp.get("name", "")
        if not name:
            continue
        if name == user_field:
            data[name] = username
        elif name == pass_field:
            data[name] = password
        else:
            data[name] = inp.get("value") or "test"
    return data
