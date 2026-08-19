"""NucleiAI Web Dashboard — FastAPI backend."""

import asyncio
import json
import subprocess
import tempfile
import os
import sys
import glob
from pathlib import Path
from datetime import datetime

from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

app = FastAPI(title="NucleiAI", version="0.1.0")

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from core.config import get_config, check_binaries
from core.ai_filter import filter_results
from core.report_generator import generate_report_data, generate_llm_summary
from core.scanner import collect_templates, _get_random_ua, _is_localhost
from core.fingerprint import fingerprint_target, suggest_templates
from core.subdomain import enumerate_subdomains, check_live_hosts, enumerate_subdomains_fallback
from core.crawler import crawl, CrawlResult
from core.session import build_headers_from_form, list_sessions, save_session, delete_session, Session
import uuid

templates = Jinja2Templates(directory=str(Path(__file__).resolve().parent / "templates"))

SCAN_HISTORY = []
CRAWL_CACHE: dict[str, CrawlResult] = {}


def _create_result(target: str = "", domain: str = "") -> dict:
    """Create a result entry with default fields."""
    return {
        "target": target,
        "domain": domain,
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

    fixed = []
    new = []
    persistent = []

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


def run_nuclei_scan(target: str, suggested_templates: list[str] | None = None,
                    include_demo: bool = False, include_community: bool = False,
                    headers: dict[str, str] | None = None) -> tuple[list[dict], list[str]]:
    """Run nuclei against target, return (parsed raw results, templates used)."""
    cfg = get_config()
    output_file = tempfile.mktemp(suffix=".jsonl")

    template_list = collect_templates(include_demo=include_demo,
                                      suggested=suggested_templates,
                                      include_community=include_community)

    args = [
        cfg["nuclei_binary"], "-target", target,
        "-jsonl", "-silent",
        "-output", output_file,
        "-timeout", "30",
        "-rate-limit", str(cfg["rate_limit"]),
        "-concurrency", str(cfg["concurrency"]),
        "-severity", cfg["severity"],
    ]
    if cfg.get("scan_delay", 0) > 0:
        args.extend(["-delay", str(cfg["scan_delay"])])
    if cfg.get("scan_retries", 0) > 0:
        args.extend(["-retries", str(cfg["scan_retries"])])
    ua = _get_random_ua()
    if ua:
        args.extend(["-H", f"User-Agent: {ua}"])
    if headers:
        for key, value in headers.items():
            args.extend(["-H", f"{key}: {value}"])
    for t in template_list:
        args.extend(["-t", t])
    if cfg.get("proxy") and not _is_localhost(target):
        args.extend(["-proxy", cfg["proxy"]])

    subprocess.run(args, timeout=cfg["timeout_per_target"], capture_output=True)

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

    return results, template_list


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
        "saved_sessions": list_sessions(),
    })


@app.post("/", response_class=HTMLResponse)
async def do_scan(request: Request, target: str = Form(...),
                  step: str = Form("scan"),
                  cookie: str = Form(""),
                  bearer: str = Form(""),
                  session_name: str = Form(""),
                  hdr_key: str = Form(""),
                  hdr_val: str = Form(""),
                  crawl_depth: int = Form(0),
                  max_pages: int = Form(50),
                  use_community: bool = Form(False)):
    """Handle scan form submission: scan or crawl -> AI filter -> show results."""
    result = _create_result(target=target)

    if not target.startswith("http"):
        result["error"] = "URL must start with http:// or https://"
        SCAN_HISTORY.insert(0, result)
        return templates.TemplateResponse("index.html", {
            "request": request,
            "title": "NucleiAI - AI增强漏洞管理平台",
            "history": SCAN_HISTORY,
            "saved_sessions": list_sessions(),
            "last_target": target,
        })

    # Build auth headers from form fields
    custom_headers = []
    if hdr_key.strip():
        custom_headers.append((hdr_key.strip(), hdr_val.strip()))
    headers = build_headers_from_form(cookie=cookie, bearer=bearer,
                                       custom_headers=custom_headers,
                                       session_name=session_name)

    # --- Crawl path ---
    if step == "crawl" or crawl_depth > 0:
        try:
            cfg = get_config()
            crawl_result = crawl(
                target,
                max_depth=crawl_depth if crawl_depth > 0 else cfg.get("crawler_max_depth", 3),
                max_pages=max_pages,
                same_domain=cfg.get("crawler_same_domain", True),
                respect_robots=cfg.get("crawler_respect_robots", True),
                headers=headers if headers else None,
            )
            crawl_id = str(uuid.uuid4())[:8]
            CRAWL_CACHE[crawl_id] = crawl_result
            SCAN_HISTORY.insert(0, result)
            return templates.TemplateResponse("index.html", {
                "request": request,
                "title": "NucleiAI - 爬取结果",
                "history": SCAN_HISTORY,
                "crawl_result": {
                    "id": crawl_id,
                    "start_url": target,
                    "urls": crawl_result.urls,
                    "forms": crawl_result.forms,
                    "pages_crawled": crawl_result.pages_crawled,
                    "errors": crawl_result.errors,
                },
                "cookie": cookie,
                "bearer": bearer,
                "session_name": session_name,
                "saved_sessions": list_sessions(),
                "last_target": target,
            })
        except Exception as e:
            result["error"] = f"爬取失败: {e}"
            SCAN_HISTORY.insert(0, result)
            return templates.TemplateResponse("index.html", {
                "request": request,
                "title": "NucleiAI - AI增强漏洞管理平台",
                "history": SCAN_HISTORY,
                "saved_sessions": list_sessions(),
                "last_target": target,
            })

    # --- Direct scan path ---
    try:
        # Run blocking scan in thread pool to avoid blocking the event loop
        import concurrent.futures
        loop = asyncio.get_event_loop()

        def _run_scan():
            suggested = []
            fp = None
            try:
                fp = fingerprint_target(target, headers=headers)
                technologies = fp.get("technologies", [])
                if technologies:
                    suggested = suggest_templates(technologies)
            except Exception:
                pass
            raw_results, tmpl_list = run_nuclei_scan(target, suggested, headers=headers,
                                                           include_community=use_community)
            return raw_results, suggested, fp

        raw_results, suggested, fp = await loop.run_in_executor(None, _run_scan)
        if fp:
            result["fingerprint"] = fp
            result["smart_templates"] = suggested

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
        result["error"] = "扫描超时"
    except Exception as e:
        result["error"] = str(e)

    SCAN_HISTORY.insert(0, result)

    return templates.TemplateResponse("index.html", {
        "request": request,
        "title": "NucleiAI - AI增强漏洞管理平台",
        "history": SCAN_HISTORY,
        "saved_sessions": list_sessions(),
        "last_target": target,
    })


@app.post("/scan-crawled", response_class=HTMLResponse)
async def scan_crawled_urls(request: Request,
                             crawl_id: str = Form(...),
                             selected_urls: list[str] = Form(...),
                             cookie: str = Form(""),
                             bearer: str = Form(""),
                             session_name: str = Form("")):
    """Scan selected URLs from a crawl result."""
    crawl_result = CRAWL_CACHE.pop(crawl_id, None)
    if not crawl_result:
        return HTMLResponse("<h3>爬取结果已过期，请重新爬取</h3>", status_code=400)

    headers = build_headers_from_form(cookie=cookie, bearer=bearer,
                                       session_name=session_name)

    pipeline_result = _create_result(domain=crawl_result.start_url)
    pipeline_result["subdomains"] = []
    pipeline_result["live_hosts"] = selected_urls
    pipeline_result["host_results"] = []

    for url in selected_urls:
        hr = {"url": url, "findings": [], "confirmed": [], "fp": [], "error": None}
        try:
            fingerprint = fingerprint_target(url, headers=headers)
            suggested = suggest_templates(fingerprint.get("technologies", []))
            raw, _ = run_nuclei_scan(url, suggested_templates=suggested, headers=headers)
            if raw:
                confirmed, fp = await filter_results(raw)
                hr["findings"] = [scan_result_to_row(r) for r in raw]
                hr["confirmed"] = [scan_result_to_row(r) for r in confirmed]
                hr["fp"] = [scan_result_to_row(r) for r in fp]
        except subprocess.TimeoutExpired:
            hr["error"] = "扫描超时"
        except Exception as e:
            hr["error"] = str(e)
        pipeline_result["host_results"].append(hr)

    SCAN_HISTORY.insert(0, pipeline_result)

    return templates.TemplateResponse("index.html", {
        "request": request,
        "title": "NucleiAI - 爬取+扫描结果",
        "history": SCAN_HISTORY,
        "pipeline": pipeline_result,
        "saved_sessions": list_sessions(),
    })


@app.post("/sessions/save", response_class=HTMLResponse)
async def save_session_endpoint(request: Request,
                                 session_name: str = Form(...),
                                 cookie: str = Form(""),
                                 bearer: str = Form("")):
    """Save current auth as a named session."""
    headers = build_headers_from_form(cookie=cookie, bearer=bearer)
    session = Session(name=session_name, headers=headers, cookie=cookie)
    save_session(session)
    return templates.TemplateResponse("index.html", {
        "request": request,
        "title": "NucleiAI - AI增强漏洞管理平台",
        "history": SCAN_HISTORY,
        "saved_sessions": list_sessions(),
        "status_msg": f"会话 '{session_name}' 已保存",
    })


@app.post("/sessions/delete", response_class=HTMLResponse)
async def delete_session_endpoint(request: Request, session_name: str = Form(...)):
    """Delete a saved session."""
    delete_session(session_name)
    return templates.TemplateResponse("index.html", {
        "request": request,
        "title": "NucleiAI - AI增强漏洞管理平台",
        "history": SCAN_HISTORY,
        "saved_sessions": list_sessions(),
        "status_msg": f"会话 '{session_name}' 已删除",
    })


@app.get("/compare", response_class=HTMLResponse)
async def compare_view(request: Request, i1: int = 0, i2: int = 1):
    """Show diff between two scan results."""
    if len(SCAN_HISTORY) < 2:
        return HTMLResponse("<h3>需要至少两次扫描结果才能对比</h3>", status_code=400)

    max_idx = len(SCAN_HISTORY) - 1
    i1 = max(0, min(i1, max_idx))
    i2 = max(0, min(i2, max_idx))

    scan_a, scan_b = SCAN_HISTORY[i1], SCAN_HISTORY[i2]
    if (scan_a.get("domain") and not scan_a.get("target")) or \
       (scan_b.get("domain") and not scan_b.get("target")):
        return HTMLResponse("<h3>资产发现结果不支持对比</h3>", status_code=400)

    diff = compare_scans(scan_a, scan_b)
    return templates.TemplateResponse("compare.html", {
        "request": request,
        "title": f"Scan Diff — {diff['scan_a_target']} vs {diff['scan_b_target']}",
        "diff": diff,
        "history": SCAN_HISTORY,
        "i1": i1,
        "i2": i2,
        "saved_sessions": list_sessions(),
    })


@app.get("/report/{index}", response_class=HTMLResponse)
async def view_report(request: Request, index: int):
    """Render a printable HTML report for a scan result."""
    if index < 0 or index >= len(SCAN_HISTORY):
        return HTMLResponse("<h3>报告不存在</h3>", status_code=404)

    scan = SCAN_HISTORY[index]
    if scan.get("domain") and not scan.get("target"):
        return HTMLResponse("<h3>资产发现结果暂不支持生成报告</h3>", status_code=400)

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
        "saved_sessions": list_sessions(),
    })


@app.post("/discover", response_class=HTMLResponse)
async def discover_assets(request: Request, domain: str = Form(...)):
    """Asset discovery: enumerate subdomains and check live hosts."""
    result = _create_result(domain=domain)

    try:
        subs = enumerate_subdomains(domain)
        result["subdomains"] = subs
        if subs:
            result["live_hosts"] = check_live_hosts(subs)
    except Exception as e:
        result["error"] = str(e)

    SCAN_HISTORY.insert(0, result)

    return templates.TemplateResponse("index.html", {
        "request": request,
        "title": "NucleiAI - 资产发现",
        "history": SCAN_HISTORY,
        "discovery": result,
        "saved_sessions": list_sessions(),
    })


@app.post("/pipeline", response_class=HTMLResponse)
async def pipeline_scan(request: Request, domain: str = Form(...),
                        cookie: str = Form(""),
                        bearer: str = Form(""),
                        session_name: str = Form("")):
    """Full automated pipeline: discover + scan + AI filter."""
    result = _create_result(domain=domain)
    result["subdomains"] = []
    result["live_hosts"] = []
    result["host_results"] = []

    headers = build_headers_from_form(cookie=cookie, bearer=bearer,
                                       session_name=session_name)

    try:
        subs = enumerate_subdomains(domain)
        if not subs:
            subs = enumerate_subdomains_fallback(domain)
        result["subdomains"] = subs
        if not subs:
            result["error"] = "未发现子域名"
        else:
            live_lines = check_live_hosts(subs)
            result["live_hosts"] = live_lines

            cfg = get_config()
            max_scan = cfg.get("max_pipeline_hosts", 10)
            for line in live_lines[:max_scan]:
                parts = line.split()
                if not parts:
                    continue
                url = parts[0].strip()
                if not url.startswith("http"):
                    url = f"http://{url}"

                host_result = {"url": url, "findings": [], "confirmed": [], "fp": [], "error": None}
                try:
                    raw_results, _ = run_nuclei_scan(url, None, include_demo=False,
                                                     headers=headers if headers else None)
                    if raw_results:
                        confirmed, fp = await filter_results(raw_results)
                        host_result["findings"] = [scan_result_to_row(r) for r in raw_results]
                        host_result["confirmed"] = [scan_result_to_row(r) for r in confirmed]
                        host_result["fp"] = [scan_result_to_row(r) for r in fp]
                except subprocess.TimeoutExpired:
                    host_result["error"] = "扫描超时"
                except Exception as e:
                    host_result["error"] = str(e)

                result["host_results"].append(host_result)

    except Exception as e:
        result["error"] = str(e)

    SCAN_HISTORY.insert(0, result)

    return templates.TemplateResponse("index.html", {
        "request": request,
        "title": "NucleiAI - 管线扫描",
        "history": SCAN_HISTORY,
        "pipeline": result,
        "saved_sessions": list_sessions(),
    })
