"""NucleiAI Web Dashboard — FastAPI backend."""

import json
import subprocess
import tempfile
import os
import sys
from pathlib import Path
from datetime import datetime

from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

app = FastAPI(title="NucleiAI", version="0.1.0")

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))
from core.ai_filter import filter_results
from core.report_generator import generate_report_data, generate_llm_summary
from core.fingerprint import fingerprint_target, suggest_templates

templates = Jinja2Templates(directory=str(Path(__file__).resolve().parent / "templates"))

SCAN_HISTORY = []


def _finding_key(r: dict) -> str:
    """Create a stable key for comparing findings across scans."""
    info = r.get("info", {})
    tid = info.get("name", r.get("template-id", "?"))
    url = r.get("url") or r.get("matched-at") or r.get("host", "") or "?"
    return f"{tid}@{url}"


def compare_scans(scan_a: dict, scan_b: dict) -> dict:
    """Compare two scan results, return fixed/new/persistent groupings."""
    raw_a = scan_a.get("_raw_results", [])
    raw_b = scan_b.get("_raw_results", [])

    keys_a = {_finding_key(r): r for r in raw_a}
    keys_b = {_finding_key(r): r for r in raw_b}

    fixed = []       # in A but not B (was fixed)
    new = []         # in B but not A (newly introduced)
    persistent = []  # in both (still there)

    for key, r in keys_a.items():
        if key not in keys_b:
            fixed.append(r)
        else:
            persistent.append(r)

    for key, r in keys_b.items():
        if key not in keys_a:
            new.append(r)

    def _to_rows(items):
        return [scan_result_to_row(r) for r in items]

    return {
        "fixed": _to_rows(fixed),
        "new": _to_rows(new),
        "persistent": _to_rows(persistent),
        "scan_a_target": scan_a["target"],
        "scan_b_target": scan_b["target"],
        "scan_a_time": scan_a["time"],
        "scan_b_time": scan_b["time"],
    }


def run_nuclei_scan(target: str, suggested_templates: list[str] | None = None) -> tuple[list[dict], list[str]]:
    """Run nuclei against target, return (parsed raw results, templates used)."""
    custom_templates = str(BASE_DIR / "custom-templates")
    output_file = tempfile.mktemp(suffix=".jsonl")

    template_args = ["-t", custom_templates]
    if suggested_templates:
        for t in suggested_templates:
            template_args.extend(["-t", t])

    args = [
        "nuclei", "-target", target,
        *template_args,
        "-jsonl", "-silent",
        "-output", output_file,
        "-timeout", "30",
    ]

    proc = subprocess.run(args, timeout=120, capture_output=True)

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

    return results, template_args


def scan_result_to_row(r: dict) -> dict:
    """Extract display fields from a scan result."""
    info = r.get("info", {})
    verdict = r.get("ai_verdict", {})
    return {
        "name": info.get("name", "Unknown"),
        "severity": info.get("severity", "info"),
        "description": info.get("description", "")[:120],
        "tags": ", ".join(info.get("tags", [])),
        "matched": r.get("matcher-name", "?"),
        "url": r.get("url", ""),
        "finding_type": verdict.get("finding_type", "?"),
        "is_false_positive": verdict.get("is_false_positive", False),
        "confidence": verdict.get("confidence", 0),
        "reason": verdict.get("reason", ""),
    }


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    """Dashboard homepage."""
    return templates.TemplateResponse("index.html", {
        "request": request,
        "title": "NucleiAI - AI增强漏洞管理平台",
        "history": SCAN_HISTORY,
    })


@app.post("/", response_class=HTMLResponse)
async def do_scan(request: Request, target: str = Form(...)):
    """Handle scan form submission: scan -> AI filter -> show results."""
    result = {
        "target": target,
        "time": datetime.now().strftime("%H:%M:%S"),
        "findings": [],
        "confirmed": [],
        "false_positives": [],
        "error": None,
        "ai_error": None,
        "count": 0,
        "ai_enabled": True,
        "_raw_results": [],
        "_summary": None,
        "fingerprint": None,
        "smart_templates": [],
    }

    if not target.startswith("http"):
        result["error"] = "URL must start with http:// or https://"
    else:
        try:
            # Step 1: Fingerprint the target
            suggested = []
            try:
                result["fingerprint"] = fingerprint_target(target)
                technologies = result["fingerprint"].get("technologies", [])
                if technologies:
                    suggested = suggest_templates(technologies)
                    result["smart_templates"] = suggested
            except Exception:
                pass  # Fingerprint is optional

            # Step 2: Run nuclei scan with smart template selection
            raw_results, used_templates = run_nuclei_scan(target, suggested)

            if raw_results:
                try:
                    confirmed, false_positives = await filter_results(raw_results)
                    result["confirmed"] = [scan_result_to_row(r) for r in confirmed]
                    result["false_positives"] = [scan_result_to_row(r) for r in false_positives]
                except Exception as e:
                    result["ai_enabled"] = False
                    result["ai_error"] = f"AI 过滤不可用: {e}"

                result["findings"] = [scan_result_to_row(r) for r in raw_results]
                result["_raw_results"] = raw_results
            result["count"] = len(raw_results)
        except subprocess.TimeoutExpired:
            result["error"] = "Scan timed out (120s)"
        except Exception as e:
            result["error"] = str(e)

    SCAN_HISTORY.insert(0, result)

    return templates.TemplateResponse("index.html", {
        "request": request,
        "title": "NucleiAI - AI增强漏洞管理平台",
        "history": SCAN_HISTORY,
    })


@app.get("/compare", response_class=HTMLResponse)
async def compare_view(request: Request, i1: int = 0, i2: int = 1):
    """Show diff between two scan results."""
    if len(SCAN_HISTORY) < 2:
        return HTMLResponse("<h3>需要至少两次扫描结果才能对比</h3>", status_code=400)

    max_idx = len(SCAN_HISTORY) - 1
    i1 = max(0, min(i1, max_idx))
    i2 = max(0, min(i2, max_idx))

    diff = compare_scans(SCAN_HISTORY[i1], SCAN_HISTORY[i2])
    return templates.TemplateResponse("compare.html", {
        "request": request,
        "title": f"Scan Diff — {diff['scan_a_target']} vs {diff['scan_b_target']}",
        "diff": diff,
        "history": SCAN_HISTORY,
        "i1": i1,
        "i2": i2,
    })


@app.get("/report/{index}", response_class=HTMLResponse)
async def view_report(request: Request, index: int):
    """Render a printable HTML report for a scan result."""
    if index < 0 or index >= len(SCAN_HISTORY):
        return HTMLResponse("<h3>报告不存在</h3>", status_code=404)

    scan = SCAN_HISTORY[index]
    raw_results = scan.get("_raw_results", [])
    confirmed_raw = [r for r in raw_results
                     if not r.get("ai_verdict", {}).get("is_false_positive", False)]
    fp_raw = [r for r in raw_results
              if r.get("ai_verdict", {}).get("is_false_positive", False)]

    report_data = generate_report_data(raw_results, confirmed_raw, fp_raw)
    report_data["scan_target"] = scan["target"]
    report_data["scan_time"] = scan["time"]

    summary = scan.get("_summary")
    if summary is None and scan.get("ai_enabled") and confirmed_raw:
        try:
            summary = await generate_llm_summary(confirmed_raw)
        except Exception:
            summary = {"overall_grade": "?", "severity_counts": {},
                       "top_issues": [], "summary": "AI摘要生成失败"}
        scan["_summary"] = summary

    return templates.TemplateResponse("report.html", {
        "request": request,
        "report": report_data,
        "summary": summary,
    })
