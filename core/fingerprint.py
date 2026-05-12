"""Target fingerprinting — identify technologies and suggest templates."""

import subprocess
import json


TECH_TEMPLATE_MAP = {
    "wordpress": ["technologies/wordpress"],
    "apache": ["technologies/apache"],
    "nginx": ["technologies/nginx"],
    "php": ["technologies/php"],
    "mysql": ["technologies/mysql"],
    "jquery": ["technologies/jquery"],
    "bootstrap": ["technologies/bootstrap"],
    "react": ["technologies/react"],
    "django": ["technologies/django"],
}


def fingerprint_target(target: str, timeout: int = 60) -> dict:
    """Run httpx to fingerprint the target, return parsed info."""
    result = subprocess.run(
        ["httpx", "-u", target, "-json", "-tech-detect", "-silent"],
        capture_output=True, text=True, timeout=timeout
    )

    info = {"url": target, "technologies": [], "status_code": None, "title": ""}

    if result.stdout.strip():
        try:
            data = json.loads(result.stdout.strip())
            info["status_code"] = data.get("status_code")
            info["title"] = data.get("title", "")
            tech_list = data.get("tech", [])
            info["technologies"] = tech_list if tech_list else []
        except json.JSONDecodeError:
            pass

    return info


def suggest_templates(technologies: list[str]) -> list[str]:
    """Suggest nuclei templates based on detected technologies."""
    templates = ["exposures/configs/common-configs"]  # always useful
    for tech in technologies:
        tech_lower = tech.lower()
        if tech_lower in TECH_TEMPLATE_MAP:
            templates.extend(TECH_TEMPLATE_MAP[tech_lower])
    return templates
