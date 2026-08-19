"""Nuclei scanner wrapper — runs scans and parses JSON output."""

import json
import os
import random
import subprocess
import tempfile
from pathlib import Path

from core.config import get_config

# Community template categories used for real-world scanning
COMMUNITY_CATEGORIES = [
    "vulnerabilities", "exposures", "misconfiguration",
    "exposed-panels", "default-logins",
]


def _get_random_ua() -> str | None:
    """Pick a random User-Agent from the config list, if any are configured."""
    cfg = get_config()
    ua_list = cfg.get("user_agents", [])
    if ua_list:
        return random.choice(ua_list)
    return None


def _is_localhost(target: str) -> bool:
    """Check if target is localhost/loopback — proxy should be skipped."""
    from urllib.parse import urlparse
    parsed = urlparse(target)
    host = parsed.hostname or ""
    return host in ("127.0.0.1", "localhost", "::1") or host.startswith("192.168.") or host.startswith("10.")


def _build_nuclei_args(target: str, output_file: str,
                       templates: list[str] | None = None,
                       severity: str | None = None,
                       headers: dict[str, str] | None = None) -> list[str]:
    """Build the nuclei command argument list from config."""
    cfg = get_config()
    args = [cfg["nuclei_binary"], "-target", target, "-jsonl", "-silent",
           "-timeout", "30",
           "-rate-limit", str(cfg.get("rate_limit", 10)),
           "-concurrency", str(cfg.get("concurrency", 10))]

    if cfg.get("proxy") and not _is_localhost(target):
        args.extend(["-proxy", cfg["proxy"]])
    if cfg.get("scan_delay", 0) > 0:
        args.extend(["-delay", str(cfg["scan_delay"])])
    if cfg.get("scan_retries", 0) > 0:
        args.extend(["-retries", str(cfg["scan_retries"])])

    # Use config severity as default if not explicitly passed
    severity = severity or cfg.get("severity", "critical,high,medium")

    ua = _get_random_ua()
    if ua:
        args.extend(["-H", f"User-Agent: {ua}"])
    if headers:
        for key, value in headers.items():
            args.extend(["-H", f"{key}: {value}"])

    if templates:
        for t in templates:
            args.extend(["-t", t])
    if severity:
        args.extend(["-severity", severity])

    args.extend(["-output", output_file])
    return args


def collect_templates(include_demo: bool = False,
                      suggested: list[str] | None = None,
                      include_community: bool = False,
                      custom_dir: str | None = None) -> list[str]:
    """Collect all templates to use for a scan.

    Returns a flat list of -t <path> pairs ready to extend into nuclei args.
    Includes: custom vulnerability templates + fingerprint-suggested templates.
    Community templates (massive, 10000+) are only included when explicitly requested.
    """
    from pathlib import Path
    import glob as _glob

    cfg = get_config()
    base_dir = Path(__file__).resolve().parent.parent
    custom_path = Path(custom_dir) if custom_dir else base_dir / "custom-templates"
    templates: list[str] = []

    # 1. Custom vulnerability templates (skip demo 01-05 unless include_demo)
    for tmpl in sorted(_glob.glob(str(custom_path / "*.yaml"))):
        fname = os.path.basename(tmpl)
        if not include_demo and fname[:2] in ("01", "02", "03", "04", "05"):
            continue
        templates.append(tmpl)

    # 2. Smart-suggested templates from fingerprinting (always included)
    if suggested:
        templates.extend(suggested)

    # 3. Community templates — only when explicitly requested (very slow)
    if include_community:
        community_dir = cfg.get("templates_dir", "")
        if community_dir:
            http_dir = os.path.join(community_dir, "http")
            if os.path.isdir(http_dir):
                for cat in COMMUNITY_CATEGORIES:
                    cp = os.path.join(http_dir, cat)
                    if os.path.isdir(cp):
                        templates.append(cp)

    return templates


def run_scan(target: str, templates: list[str] | None = None,
             severity: str | None = None, timeout: int = 300,
             headers: dict[str, str] | None = None) -> list[dict]:
    """Run nuclei scan against a target, return parsed results."""
    output_file = tempfile.mktemp(suffix=".jsonl")
    args = _build_nuclei_args(target, output_file, templates, severity, headers)

    subprocess.run(args, timeout=timeout, capture_output=True)

    results = []
    if os.path.exists(output_file):
        with open(output_file, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        results.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
        os.unlink(output_file)

    return results


def get_template_list() -> list[str]:
    """List available nuclei templates."""
    cfg = get_config()
    result = subprocess.run(
        [cfg["nuclei_binary"], "-tl"], capture_output=True, text=True, timeout=30
    )
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]
