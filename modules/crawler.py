"""Session-aware same-origin crawling and generic login support."""

import logging
from urllib.parse import urldefrag, urljoin, urlparse

import requests
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)
HEADERS = {"User-Agent": "VulnRadar educational scanner/2.1"}
REQUEST_TIMEOUT = 10


def create_session() -> requests.Session:
    session = requests.Session()
    session.headers.update(HEADERS)
    return session


def login_to_target(session: requests.Session, target_url: str, username: str, password: str) -> dict:
    """Find and submit a likely login form without assuming field names."""
    result = {"success": False, "message": "Login was not attempted.", "final_url": target_url, "status_code": None}
    try:
        response = session.get(target_url, timeout=REQUEST_TIMEOUT, verify=False, allow_redirects=True)
        result.update(final_url=response.url, status_code=response.status_code)
        logger.info("Login page GET: status=%s final_url=%s", response.status_code, _safe_log_url(response.url))
        soup = BeautifulSoup(response.text, "html.parser")
        form = _find_login_form(soup)
        if form is None:
            result["message"] = "No login form with username and password fields was found."
            return result
        user_field = _find_username_field(form)
        password_field = form.find("input", attrs={"type": "password"})
        data = {}
        for tag in form.find_all(["input", "textarea", "select"]):
            name = tag.get("name")
            if not name:
                continue
            if tag is user_field:
                data[name] = username
            elif tag is password_field:
                data[name] = password
            elif tag.name == "select":
                option = tag.find("option", selected=True) or tag.find("option")
                data[name] = option.get("value", "") if option else ""
            elif tag.get("type", "text").lower() == "submit":
                data[name] = tag.get("value", "")
            elif tag.get("type", "text").lower() not in {"button", "image", "file"}:
                data[name] = tag.get("value", "")

        action = urljoin(response.url, form.get("action") or response.url)
        before_url = response.url
        method = (form.get("method") or "post").lower()
        if method == "get":
            logged_in = session.get(action, params=data, timeout=REQUEST_TIMEOUT, verify=False, allow_redirects=True)
        else:
            logged_in = session.post(action, data=data, timeout=REQUEST_TIMEOUT, verify=False, allow_redirects=True)
        result.update(final_url=logged_in.url, status_code=logged_in.status_code)
        logger.info("Login submit: status=%s final_url=%s", logged_in.status_code, _safe_log_url(logged_in.url))
        body = logged_in.text.lower()
        failure_terms = ("invalid username", "incorrect password", "login failed", "authentication failed")
        success_markers = ("logout", "log out", "sign out", "welcome", "dashboard", "my account")
        redirected = logged_in.url.rstrip("/") != before_url.rstrip("/")
        result["success"] = bool(logged_in.ok and not any(term in body for term in failure_terms) and (any(marker in body for marker in success_markers) or redirected))
        result["message"] = "Login succeeded; authenticated session established." if result["success"] else "Login response did not indicate successful authentication."
    except requests.RequestException as exc:
        result["message"] = f"Login request failed: {exc}"
    return result


def crawl_authenticated_pages(session: requests.Session, target_url: str, max_pages: int = 25) -> dict:
    """Crawl same-origin HTML pages and return pages, links, and reproducible forms."""
    origin = urlparse(target_url)
    queue, visited, pages, forms, links = [_normalise_url(target_url)], set(), [], [], []
    limit = max(1, min(int(max_pages or 25), 250))
    while queue and len(pages) < limit:
        url = queue.pop(0)
        if url in visited or not _same_origin(url, origin) or not _safe_navigation(url):
            continue
        visited.add(url)
        try:
            response = session.get(url, timeout=REQUEST_TIMEOUT, verify=False, allow_redirects=True)
            final_url = _normalise_url(response.url)
            if not _same_origin(final_url, origin) or "text/html" not in response.headers.get("Content-Type", "text/html").lower():
                continue
            soup = BeautifulSoup(response.text, "html.parser")
            page_forms = [_parse_form(tag, final_url) for tag in soup.find_all("form")]
            page_links = []
            for anchor in soup.find_all("a", href=True):
                candidate = _normalise_url(urljoin(final_url, anchor["href"]))
                if _same_origin(candidate, origin) and _safe_navigation(candidate) and candidate not in page_links:
                    page_links.append(candidate)
                    if candidate not in visited and candidate not in queue:
                        queue.append(candidate)
            pages.append({"url": final_url, "status_code": response.status_code, "title": soup.title.get_text(strip=True) if soup.title else ""})
            forms.extend(page_forms)
            links.extend(link for link in page_links if link not in links)
        except requests.RequestException as exc:
            logger.debug("Crawler request error for %s: %s", url, exc)
    return {"pages": pages, "forms": forms, "links": links, "pages_discovered": len(pages), "forms_discovered": len(forms)}


def crawl_forms(base_url: str, session: requests.Session | None = None, max_pages: int = 25) -> list[dict]:
    """Backward-compatible form-only crawler with optional session support."""
    result = crawl_authenticated_pages(session or create_session(), base_url, max_pages)
    return result["forms"] or [{"page_url": _normalise_url(base_url), "action": _normalise_url(base_url), "method": "get", "inputs": [{"name": "q", "type": "text", "value": ""}]}]


def _find_login_form(soup):
    for form in soup.find_all("form"):
        if form.find("input", attrs={"type": "password"}) and _find_username_field(form):
            return form
    return None


def _find_username_field(form):
    fields = form.find_all("input")
    for field in fields:
        name = (field.get("name") or "").lower()
        if field.get("type", "text").lower() in {"text", "email"} and any(k in name for k in ("user", "email", "login", "name")):
            return field
    return next((field for field in fields if field.get("type", "text").lower() in {"text", "email"}), None)


def _parse_form(form_tag, page_url: str) -> dict:
    inputs = []
    for tag in form_tag.find_all(["input", "textarea", "select"]):
        name = tag.get("name", "")
        if not name:
            continue
        value = tag.get("value", "")
        if tag.name == "select":
            option = tag.find("option", selected=True) or tag.find("option")
            value = option.get("value", "") if option else ""
        inputs.append({"name": name, "type": tag.get("type", "text"), "value": value})
    return {"page_url": page_url, "action": urljoin(page_url, form_tag.get("action") or page_url), "method": (form_tag.get("method") or "get").lower(), "inputs": inputs}


def _normalise_url(url: str) -> str:
    clean, _ = urldefrag(url)
    parsed = urlparse(clean)
    return parsed._replace(path=parsed.path or "/").geturl()


def _safe_log_url(url: str) -> str:
    """Keep query strings out of diagnostics because a GET login can contain secrets."""
    parsed = urlparse(url)
    return parsed._replace(query="", fragment="").geturl()


def _same_origin(url: str, origin) -> bool:
    parsed = urlparse(url)
    return parsed.scheme in {"http", "https"} and parsed.scheme == origin.scheme and parsed.netloc == origin.netloc


def _safe_navigation(url: str) -> bool:
    """Avoid state-changing sign-out links during an authenticated crawl."""
    path = urlparse(url).path.lower().rstrip("/")
    return not any(token in path.rsplit("/", 1)[-1] for token in ("logout", "signout", "sign-out", "logoff"))
