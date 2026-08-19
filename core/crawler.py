"""BFS web crawler — discovers URLs and forms from HTML pages."""

import time
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse, urldefrag
from urllib.robotparser import RobotFileParser

import httpx
from bs4 import BeautifulSoup

from core.config import get_config


@dataclass
class CrawlResult:
    urls: list[str]
    forms: list[dict]
    pages_crawled: int
    start_url: str
    errors: list[str] = field(default_factory=list)


def _normalize_url(url: str) -> str:
    """Strip fragment, lowercase hostname, remove default ports."""
    url, _ = urldefrag(url)
    parsed = urlparse(url)
    netloc = parsed.netloc.lower()
    if netloc.endswith(":80"):
        netloc = netloc[:-3]
    elif netloc.endswith(":443"):
        netloc = netloc[:-4]
    scheme = parsed.scheme.lower() or "https"
    path = parsed.path or "/"
    return f"{scheme}://{netloc}{path}"


def _same_domain(url1: str, url2: str) -> bool:
    return urlparse(url1).netloc.lower() == urlparse(url2).netloc.lower()


def _is_allowed_by_robots(url: str, user_agent: str = "*") -> bool:
    parsed = urlparse(url)
    robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
    try:
        rp = RobotFileParser()
        rp.set_url(robots_url)
        rp.read()
        return rp.can_fetch(user_agent, url)
    except Exception:
        return True


def _extract_links(html: str, base_url: str) -> list[str]:
    soup = BeautifulSoup(html, "lxml")
    links = []
    for a in soup.find_all("a", href=True):
        href = a["href"].strip()
        if href and not href.startswith(("#", "javascript:", "mailto:", "tel:", "data:")):
            links.append(urljoin(base_url, href))
    return links


def _extract_forms(html: str, base_url: str) -> list[dict]:
    soup = BeautifulSoup(html, "lxml")
    forms = []
    for form in soup.find_all("form"):
        action = form.get("action", "")
        method = form.get("method", "get").upper()
        action = urljoin(base_url, action) if action else base_url
        inputs = []
        for inp in form.find_all(["input", "select", "textarea"]):
            name = inp.get("name", "")
            if name:
                inputs.append(name)
        forms.append({"action": action, "method": method, "inputs": inputs})
    return forms


def _is_page_like(href: str) -> bool:
    parsed = urlparse(href)
    path = parsed.path.lower()
    skip_ext = (
        ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
        ".css", ".js", ".woff", ".woff2", ".ttf", ".eot",
        ".pdf", ".zip", ".tar", ".gz", ".mp4", ".mp3", ".avi",
        ".doc", ".docx", ".xls", ".xlsx",
    )
    if path.endswith(skip_ext):
        return False
    if parsed.scheme not in ("http", "https"):
        return False
    return True


def crawl(target_url: str,
          max_depth: int = 3,
          max_pages: int = 50,
          same_domain: bool = True,
          respect_robots: bool = True,
          headers: dict[str, str] | None = None) -> CrawlResult:
    """BFS crawl starting from target_url."""
    start_normalized = _normalize_url(target_url)
    visited: set[str] = set()
    discovered_urls: set[str] = set()
    discovered_forms: list[dict] = []
    errors: list[str] = []
    queue: list[tuple[str, int]] = [(start_normalized, 0)]
    pages_crawled = 0

    request_headers = dict(headers) if headers else {}
    if "User-Agent" not in request_headers:
        cfg = get_config()
        ua_list = cfg.get("user_agents", [])
        if ua_list:
            import random
            request_headers["User-Agent"] = random.choice(ua_list)
        else:
            request_headers["User-Agent"] = "Mozilla/5.0 (compatible; NucleiAI-Crawler/1.0)"

    with httpx.Client(timeout=30, follow_redirects=True,
                      headers=request_headers) as client:
        while queue and pages_crawled < max_pages:
            current_url, depth = queue.pop(0)
            if current_url in visited:
                continue
            visited.add(current_url)

            if respect_robots and not _is_allowed_by_robots(current_url):
                continue

            try:
                resp = client.get(current_url)
                if resp.status_code >= 400:
                    continue
                content_type = resp.headers.get("content-type", "")
                if "text/html" not in content_type and "application/xhtml" not in content_type:
                    continue
                html = resp.text
            except Exception as e:
                errors.append(f"{current_url}: {e}")
                continue

            pages_crawled += 1
            discovered_urls.add(current_url)

            try:
                discovered_forms.extend(_extract_forms(html, current_url))
            except Exception:
                pass

            if depth < max_depth:
                try:
                    links = _extract_links(html, current_url)
                except Exception:
                    links = []
                for link in links:
                    if not _is_page_like(link):
                        continue
                    normalized = _normalize_url(link)
                    if normalized in visited:
                        continue
                    if same_domain and not _same_domain(normalized, start_normalized):
                        continue
                    queue.append((normalized, depth + 1))

            time.sleep(0.1)

    return CrawlResult(
        urls=sorted(discovered_urls),
        forms=discovered_forms,
        pages_crawled=pages_crawled,
        start_url=target_url,
        errors=errors,
    )
