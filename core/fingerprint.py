"""Target fingerprinting — identify technologies and suggest templates."""

import subprocess
import json
import shutil
from pathlib import Path

# Map technology keywords to nuclei template paths (relative to nuclei-templates dir)
TECH_TEMPLATE_MAP = {
    "python": ["http/technologies/autobahn-python-detect.yaml"],
    "django": ["http/technologies/django-detect.yaml"],
    "flask": ["http/technologies/flask-detect.yaml"],
    "node.js": ["http/technologies/node-red-detect.yaml"],
    "react": ["http/technologies/react-detect.yaml"],
    "spring": ["http/technologies/spring-detect.yaml"],
    "apache": ["http/technologies/apache/"],
    "nginx": ["http/technologies/nginx/"],
    "iis": ["http/technologies/microsoft-iis-8.yaml"],
    "php": ["http/technologies/php-detect.yaml"],
    "jquery": ["http/technologies/jquery-detect.yaml"],
    "bootstrap": ["http/technologies/bootstrap-detect.yaml"],
}


def _find_httpx() -> str:
    """Find httpx binary in common locations."""
    # Check PATH first
    path = shutil.which("httpx")
    if path:
        return path
    # Check same directory as nuclei
    for loc in [Path.home() / "bin" / "httpx.exe",
                Path("C:/Users/14940/bin/httpx.exe")]:
        if loc.exists():
            return str(loc)
    return "httpx"


def fingerprint_target(target: str, timeout: int = 60) -> dict:
    """Run httpx to fingerprint the target, return parsed info."""
    httpx_bin = _find_httpx()
    result = subprocess.run(
        [httpx_bin, "-u", target, "-tech-detect", "-silent",
         "-json", "-title", "-status-code", "-web-server", "-content-type"],
        capture_output=True, text=True, timeout=timeout
    )

    info = {
        "url": target,
        "technologies": [],
        "status_code": None,
        "title": "",
        "web_server": "",
        "content_type": "",
    }

    if result.stdout.strip():
        try:
            data = json.loads(result.stdout.strip())
            info["status_code"] = data.get("status_code")
            info["title"] = data.get("title") or ""
            info["web_server"] = data.get("webserver") or ""
            info["content_type"] = data.get("content_type") or ""
            tech_list = data.get("tech", [])
            info["technologies"] = tech_list if tech_list else []
        except json.JSONDecodeError:
            pass

    return info


NUCLEI_TEMPLATES_DIR = None


def _find_templates_dir() -> str | None:
    """Find the nuclei-templates directory."""
    candidates = [
        Path.home() / "nuclei-templates",
        Path.home() / ".nuclei-templates",
        Path("C:/Users/14940/nuclei-templates"),
    ]
    for p in candidates:
        if p.is_dir():
            return str(p)
    return None


def suggest_templates(technologies: list[str]) -> list[str]:
    """Suggest nuclei template paths based on detected technologies.

    Returns full paths to template files/directories, ready for `nuclei -t`.
    """
    global NUCLEI_TEMPLATES_DIR
    if NUCLEI_TEMPLATES_DIR is None:
        NUCLEI_TEMPLATES_DIR = _find_templates_dir()

    if not NUCLEI_TEMPLATES_DIR:
        return []

    base = Path(NUCLEI_TEMPLATES_DIR)
    templates = []
    for tech in technologies:
        tech_name = tech.split(":")[0].lower()
        tokens = set(tech_name.replace("/", " ").replace("-", " ").split())
        for map_key, map_paths in TECH_TEMPLATE_MAP.items():
            if map_key in tokens or tech_name == map_key:
                for t in map_paths:
                    full_path = base / t
                    if full_path.exists():
                        templates.append(str(full_path))
                break
    seen = set()
    result = []
    for t in templates:
        if t not in seen:
            seen.add(t)
            result.append(t)
    return result
