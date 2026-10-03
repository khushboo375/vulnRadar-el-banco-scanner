"""
modules/crawler.py
------------------
Crawls a target URL and extracts all HTML forms with their fields and actions.
This gives the scanner a list of attack surfaces to probe.
"""

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import logging

logger = logging.getLogger(__name__)

# Common browser headers so the target doesn't reject us
HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    )
}

REQUEST_TIMEOUT = 10  # seconds


def crawl_forms(base_url: str) -> list[dict]:
    """
    Fetch the page at base_url and return a list of all <form> elements found.

    Each form dict contains:
      - action  : absolute URL the form submits to
      - method  : GET or POST
      - inputs  : list of { name, type, value } for each <input>/<textarea>
    """
    forms = []

    try:
        response = requests.get(base_url, headers=HEADERS, timeout=REQUEST_TIMEOUT, verify=False)
        response.raise_for_status()
    except requests.RequestException as exc:
        logger.warning(f"Crawler could not reach {base_url}: {exc}")
        return forms

    soup = BeautifulSoup(response.text, "html.parser")

    for form_tag in soup.find_all("form"):
        form_data = _parse_form(form_tag, base_url)
        forms.append(form_data)
        logger.debug(f"Found form → action={form_data['action']} method={form_data['method']}")

    # If no forms found on the base page, still return the base URL as a
    # target so URL-parameter tests can run.
    if not forms:
        forms.append({
            "action": base_url,
            "method": "get",
            "inputs": [{"name": "q", "type": "text", "value": ""}]
        })

    return forms


def _parse_form(form_tag, base_url: str) -> dict:
    """Extract action, method, and inputs from a BeautifulSoup <form> tag."""
    action = form_tag.get("action", "")
    method = form_tag.get("method", "get").lower()

    # Resolve relative URLs
    action = urljoin(base_url, action) if action else base_url

    inputs = []
    # Grab all input, textarea, and select elements
    for tag in form_tag.find_all(["input", "textarea", "select"]):
        inp = {
            "name": tag.get("name", ""),
            "type": tag.get("type", "text"),
            "value": tag.get("value", "")
        }
        # Skip submit buttons and hidden fields for injection (we keep them for form submission)
        inputs.append(inp)

    return {"action": action, "method": method, "inputs": inputs}
