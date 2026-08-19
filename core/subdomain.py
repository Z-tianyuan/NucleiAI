"""Subdomain discovery — Certificate Transparency logs + httpx live check."""

import json
import os
import subprocess
import tempfile
import urllib.request
import ssl

from core.config import get_config

# crt.sh API, no auth required
CRTSH_URL = "https://crt.sh/?q=%25.{}&output=json"


def enumerate_subdomains(domain: str) -> list[str]:
    """Query crt.sh for subdomains of the given domain."""
    url = CRTSH_URL.format(domain)

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    try:
        resp = urllib.request.urlopen(req, timeout=30, context=ctx)
        data = json.loads(resp.read().decode())
    except Exception as e:
        print(f"[!] crt.sh query failed: {e}")
        return []

    subs = set()
    for entry in data:
        name = entry.get("name_value", "")
        for n in name.split("\n"):
            n = n.strip().lower()
            if n.endswith("." + domain) or n == domain:
                if n.startswith("*."):
                    n = n[2:]
                subs.add(n)

    return sorted(subs)


# Fallback subdomains when crt.sh is unreachable
COMMON_SUBS = [
    "www", "api", "cdn", "dev", "staging", "app", "docs", "mail",
    "shop", "blog", "admin", "portal", "support", "status", "m",
    "test", "vpn", "assets", "static", "media", "files", "download",
    "help", "kb", "wiki", "news", "careers", "jobs", "about",
    "login", "dashboard", "my", "secure", "payment", "store",
]


def enumerate_subdomains_fallback(domain: str) -> list[str]:
    """Use common subdomain prefix list as fallback when crt.sh unavailable."""
    subs = set()
    for sub in COMMON_SUBS:
        subs.add(f"{sub}.{domain}")
    return sorted(subs)


def check_live_hosts(targets: list[str], timeout: int = 10) -> list[str]:
    """Use httpx to check which targets are alive (HTTP/HTTPS)."""
    if not targets:
        return []

    tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False, encoding="utf-8")
    tmp.write("\n".join(targets))
    tmp.close()

    cfg = get_config()
    args = [
        cfg["httpx_binary"], "-l", tmp.name, "-silent", "-timeout", str(timeout),
        "-status-code", "-title", "-tech-detect", "-no-color",
        "-tls-probe", "-retries", "1",
    ]
    if cfg.get("proxy"):
        args.extend(["-proxy", cfg["proxy"]])

    result = subprocess.run(args, capture_output=True, text=True, timeout=300)

    os.unlink(tmp.name)

    lines = []
    for line in result.stdout.strip().split("\n"):
        if line.strip():
            lines.append(line.strip())
    return lines
