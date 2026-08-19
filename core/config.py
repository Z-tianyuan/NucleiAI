"""Central configuration loader — reads config.yaml with sensible defaults."""

import os
import shutil
import sys
from pathlib import Path

import yaml

_CFG = None  # cached config dict

BASE_DIR = Path(__file__).resolve().parent.parent
CONFIG_PATH = BASE_DIR / "config.yaml"


def _resolve_binary(name: str, configured: str) -> str:
    """Find a binary: user-specified > PATH lookup > common locations."""
    if configured and Path(configured).exists():
        return configured

    candidates = []

    # Check same directory as the project first
    candidates.append(str(BASE_DIR / f"{name}.exe"))
    candidates.append(str(BASE_DIR / name))

    # Check PATH
    found = shutil.which(name)
    if found:
        candidates.append(found)

    # Check common Windows paths
    candidates.append(str(Path.home() / "bin" / f"{name}.exe"))
    candidates.append(str(Path.home() / "bin" / name))

    for c in candidates:
        if Path(c).exists():
            return c

    # Fall back to PATH result or just the name
    return found or name


def _resolve_templates_dir(configured: str) -> str:
    """Find nuclei-templates directory."""
    if configured and Path(configured).is_dir():
        return configured

    candidates = [
        BASE_DIR / "nuclei-templates",
        Path.home() / "nuclei-templates",
        Path.home() / ".nuclei-templates",
    ]
    for p in candidates:
        if p.is_dir():
            return str(p)
    return ""


def _load_config() -> dict:
    """Load and process config.yaml."""
    if CONFIG_PATH.exists():
        with open(CONFIG_PATH, encoding="utf-8") as f:
            cfg = yaml.safe_load(f) or {}
    else:
        cfg = {}

    # Flatten the structure
    paths = cfg.get("paths", {})
    network = cfg.get("network", {})
    ollama = cfg.get("ollama", {})
    server = cfg.get("server", {})
    scan = cfg.get("scan", {})
    auth = cfg.get("auth", {})
    crawler = cfg.get("crawler", {})

    return {
        # Binary paths — auto-detect if not configured
        "nuclei_binary": _resolve_binary("nuclei", paths.get("nuclei_binary", "")),
        "httpx_binary": _resolve_binary("httpx", paths.get("httpx_binary", "")),
        "templates_dir": _resolve_templates_dir(paths.get("templates_dir", "")),
        # Proxy — empty string means no proxy
        "proxy": network.get("proxy", ""),
        "timeout": network.get("timeout", 300),
        # Ollama
        "ollama_host": ollama.get("host", "http://localhost:11434"),
        "ollama_model": ollama.get("model", "qwen3:8b"),
        "ollama_timeout": ollama.get("timeout", 120),
        # Server
        "server_host": server.get("host", "127.0.0.1"),
        "server_port": server.get("port", 8080),
        # Auth
        "sessions_dir": auth.get("sessions_dir", "./sessions"),
        # Crawler
        "crawler_max_depth": crawler.get("max_depth", 3),
        "crawler_max_pages": crawler.get("max_pages", 50),
        "crawler_same_domain": crawler.get("same_domain", True),
        "crawler_respect_robots": crawler.get("respect_robots", True),
        # Scan
        "output_dir": scan.get("output_dir", "./results"),
        "concurrency": scan.get("concurrency", 10),
        "rate_limit": scan.get("rate_limit", 15),
        "severity": scan.get("severity", "critical,high,medium"),
        "timeout_per_target": scan.get("timeout_per_target", 300),
        "scan_delay": scan.get("delay", 0),
        "scan_retries": scan.get("retries", 1),
        "max_pipeline_hosts": scan.get("max_pipeline_hosts", 10),
        "user_agents": scan.get("user_agents", []),
    }


def get_config() -> dict:
    """Return the processed configuration (cached)."""
    global _CFG
    if _CFG is None:
        _CFG = _load_config()
    return _CFG


def reload_config() -> dict:
    """Force reload configuration from disk."""
    global _CFG
    _CFG = None
    return get_config()


def check_binaries() -> list[str]:
    """Check that required binaries exist. Returns list of missing binary names."""
    cfg = get_config()
    missing = []
    for key, label in [("nuclei_binary", "nuclei"), ("httpx_binary", "httpx")]:
        path = cfg.get(key, "")
        if not path or not Path(path).exists():
            missing.append(label)
    return missing
