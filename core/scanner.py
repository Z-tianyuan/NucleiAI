"""Nuclei scanner wrapper — runs scans and parses JSON output."""

import json
import subprocess
import tempfile
import os
from pathlib import Path


def run_scan(target: str, templates: list[str] | None = None,
             severity: str | None = None, timeout: int = 300) -> list[dict]:
    """Run nuclei scan against a target, return parsed results."""
    args = ["nuclei", "-target", target, "-json", "-silent"]

    if templates:
        for t in templates:
            args.extend(["-t", t])
    if severity:
        args.extend(["-severity", severity])

    output_file = tempfile.mktemp(suffix=".jsonl")
    args.extend(["-output", output_file])

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
    result = subprocess.run(
        ["nuclei", "-tl"], capture_output=True, text=True, timeout=30
    )
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]
