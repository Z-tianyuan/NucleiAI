"""NucleiAI Web Dashboard — FastAPI backend."""

import asyncio
import subprocess
import os
import sys
import threading
from pathlib import Path
from datetime import datetime

from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.templating import Jinja2Templates

app = FastAPI(title="NucleiAI", version="0.1.0")

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from core.config import get_config
from core.ai_filter import filter_results
from core.report_generator import generate_report_data, generate_llm_summary
from core.scanner import collect_templates, run_scan
from core.fingerprint import fingerprint_target, suggest_templates
from core.subdomain import enumerate_subdomains, check_live_hosts, enumerate_subdomains_fallback
from core.crawler import crawl, CrawlResult
from core.session import build_headers_from_form, list_sessions, save_session, delete_session, Session
import uuid
from urllib.parse import quote

templates = Jinja2Templates(directory=str(Path(__file__).resolve().parent / "templates"))

SCAN_HISTORY = []
CRAWL_CACHE: dict[str, CrawlResult] = {}
SCAN_TASKS: dict[str, dict] = {}
TASK_LOCK = threading.Lock()


def _auth_token() -> str:
    """Return the panel access token: env NUCLEIAI_TOKEN takes precedence over config."""
    token = os.environ.get("NUCLEIAI_TOKEN", "").strip()
    if token:
        return token
    return str(get_config().get("auth_token", "") or "").strip()


@app.middleware("http")
async def auth_guard(request: Request, call_next):
    """Require a token when configured. GET 请求跳转登录页，其余请求返回 401。"""
    token = _auth_token()
    if not token:
        return await call_next(request)

    path = request.url.path
    if path.startswith(("/login", "/static", "/health", "/logout")):
        return await call_next(request)

    supplied = request.headers.get("X-NucleiAI-Token") or request.cookies.get("nucleiai_token")
    if supplied and supplied == token:
        return await call_next(request)

    if request.method == "GET":
        return RedirectResponse(f"/login?next={quote(path)}", status_code=303)
    return JSONResponse({"detail": "unauthorized"}, status_code=401)


LOGIN_PAGE = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <title>NucleiAI 登录</title>
  <style>
    body { font-family: system-ui, sans-serif; background:#0f172a; color:#e2e8f0;
           display:flex; align-items:center; justify-content:center; height:100vh; margin:0; }
    .card { background:#1e293b; padding:2rem; border-radius:12px; width:320px; }
    h1 { font-size:1.1rem; margin:0 0 1rem; }
    input { width:100%; box-sizing:border-box; padding:0.6rem; border-radius:6px;
            border:1px solid #334155; background:#0f172a; color:#e2e8f0; margin-bottom:0.8rem; }
    button { width:100%; padding:0.6rem; border:0; border-radius:6px; background:#2563eb;
             color:#fff; cursor:pointer; font-size:0.95rem; }
    .err { color:#fca5a5; font-size:0.8rem; margin-bottom:0.6rem; }
  </style>
</head>
<body>
  <form class="card" method="post" action="/login">
    <h1>🔐 NucleiAI 面板访问控制</h1>
    <div class="err">__ERROR__</div>
    <input type="password" name="token" placeholder="访问令牌" autofocus required>
    <input type="hidden" name="next" value="__NEXT__">
    <button type="submit">进入面板</button>
  </form>
</body>
</html>"""


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, next: str = "/"):
    return HTMLResponse(LOGIN_PAGE.replace("__NEXT__", quote(next)).replace("__ERROR__", ""))


@app.post("/login")
async def login(request: Request, token: str = Form(...), next: str = Form("/")):
    if token == _auth_token():
        resp = RedirectResponse(next if next.startswith("/") else "/", status_code=303)
        resp.set_cookie("nucleiai_token", token, httponly=True, samesite="strict",
                        max_age=12 * 3600, path="/")
        return resp
    return HTMLResponse(LOGIN_PAGE.replace("__NEXT__", quote(next))
                        .replace("__ERROR__", "访问令牌不正确"), status_code=401)


@app.get("/logout")
async def logout():
    resp = RedirectResponse("/login", status_code=303)
    resp.delete_cookie("nucleiai_token", path="/")
    return resp


@app.get("/health")
async def health():
    return {"status": "ok"}


def _create_result(target: str = "", domain: str = "") -> dict:
    """Create a result entry with default fields."""
    return {
        "target": target,
        "domain": domain,
        "time": datetime.now().strftime("%H:%M:%S"),
        "findings": [],
        "confirmed": [],
        "false_positives": [],
        "needs_review": [],
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
                    headers: dict[str, str] | None = None,
                    progress_cb=None) -> tuple[list[dict], list[str]]:
    """Run nuclei against target, return (parsed raw results, templates used).

    委托给 core.scanner.run_scan，避免两份重复的参数构建逻辑。
    """
    cfg = get_config()
    template_list = collect_templates(include_demo=include_demo,
                                      suggested=suggested_templates,
                                      include_community=include_community)
    results = run_scan(target, templates=template_list,
                       severity=cfg.get("severity", "critical,high,medium"),
                       timeout=cfg.get("timeout_per_target", 600),
                       headers=headers,
                       progress_cb=progress_cb)
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
        "needs_review": verdict.get("needs_review", False),
        "confidence": verdict.get("confidence", 0),
        "reason": verdict.get("reason", ""),
    }


# ---------------------------------------------------------------------------
# 后台任务：爬取 / 扫描 / 管线 全部异步执行，前端轮询 /api/task/<id> 看进度
# ---------------------------------------------------------------------------

def _new_task(kind: str) -> dict:
    task = {
        "id": uuid.uuid4().hex[:12],
        "kind": kind,
        "stage": "queued",
        "progress": 0.0,
        "message": "任务已创建，等待执行…",
        "pages": 0,
        "urls_found": 0,
        "findings": 0,
        "error": None,
        "redirect": "/",
        "created": datetime.now().strftime("%H:%M:%S"),
        "updated": datetime.now().strftime("%H:%M:%S"),
    }
    with TASK_LOCK:
        SCAN_TASKS[task["id"]] = task
        # 只保留最近 100 个任务，防止字典无限增长
        if len(SCAN_TASKS) > 100:
            for k in list(SCAN_TASKS)[:-100]:
                SCAN_TASKS.pop(k, None)
    return task


def _update_task(task: dict, **kw) -> None:
    kw["updated"] = datetime.now().strftime("%H:%M:%S")
    with TASK_LOCK:
        task.update(kw)


def _start_task(kind: str, fn, args=(), **task_fields) -> dict:
    task = _new_task(kind)
    _update_task(task, **task_fields)
    threading.Thread(target=fn, args=(task, *args), daemon=True).start()
    return task


def _run_crawl_task(task, target, crawl_depth, max_pages, headers):
    cfg = get_config()

    def on_progress(pages, urls_found, current_url):
        _update_task(
            task,
            stage="crawling",
            progress=min(pages / max(max_pages, 1), 0.95),
            pages=pages,
            urls_found=urls_found,
            message=f"正在爬取: {current_url}",
        )

    crawl_result = crawl(
        target,
        max_depth=crawl_depth if crawl_depth > 0 else cfg.get("crawler_max_depth", 3),
        max_pages=max_pages,
        same_domain=cfg.get("crawler_same_domain", True),
        respect_robots=cfg.get("crawler_respect_robots", True),
        headers=headers if headers else None,
        progress_cb=on_progress,
    )

    crawl_id = str(uuid.uuid4())[:8]
    CRAWL_CACHE[crawl_id] = crawl_result
    view = {
        "id": crawl_id,
        "start_url": target,
        "urls": crawl_result.urls,
        "forms": crawl_result.forms,
        "pages_crawled": crawl_result.pages_crawled,
        "errors": crawl_result.errors,
    }
    result = _create_result(target=target)
    with TASK_LOCK:
        SCAN_HISTORY.insert(0, result)
    _update_task(
        task,
        stage="done",
        progress=1.0,
        pages=crawl_result.pages_crawled,
        urls_found=len(crawl_result.urls),
        message=f"爬取完成：{crawl_result.pages_crawled} 页 / {len(crawl_result.urls)} 个 URL",
        crawl_id=crawl_id,
        crawl_view=view,
        redirect=f"/crawl/{task['id']}",
    )


def _run_scan_task(task, target, headers, use_community):
    result = _create_result(target=target)
    _update_task(task, stage="scanning", progress=0.05, message="正在指纹识别…")
    suggested = []
    fp = None
    try:
        fp = fingerprint_target(target, headers=headers)
        technologies = fp.get("technologies", [])
        if technologies:
            suggested = suggest_templates(technologies)
    except Exception:
        pass

    _update_task(task, stage="scanning", progress=0.15,
                 message="Nuclei 扫描中，可能需要几分钟…")
    raw_results = []
    try:
        def on_scan_progress(found, elapsed):
            _update_task(
                task,
                stage="scanning",
                progress=0.15 + 0.2 * min(found / 20.0, 1.0),
                findings=found,
                message=f"Nuclei 扫描中（已发现 {found} 条，运行 {elapsed}s）…",
            )

        raw_results, _ = run_nuclei_scan(target, suggested, headers=headers,
                                         include_community=use_community,
                                         progress_cb=on_scan_progress)
    except subprocess.TimeoutExpired:
        result["error"] = "扫描超时"
    except Exception as e:
        result["error"] = str(e)

    _update_task(task, stage="scanning", progress=0.35, findings=len(raw_results),
                 message=f"Nuclei 扫描完成，{len(raw_results)} 条原始结果")

    if fp:
        result["fingerprint"] = fp
        result["smart_templates"] = suggested

    if raw_results and not result.get("error"):
        try:
            total = len(raw_results)

            def on_ai_progress(done, total_count):
                _update_task(
                    task,
                    stage="ai_filtering",
                    progress=0.35 + 0.6 * (done / max(total_count, 1)),
                    findings=done,
                    message=f"AI 分析中 {done}/{total_count} 条…",
                )

            confirmed, false_positives, needs_review = asyncio.run(
                filter_results(raw_results, progress_cb=on_ai_progress)
            )
            result["confirmed"] = [scan_result_to_row(r) for r in confirmed]
            result["false_positives"] = [scan_result_to_row(r) for r in false_positives]
            result["needs_review"] = [scan_result_to_row(r) for r in needs_review]
        except Exception as e:
            result["ai_enabled"] = False
            result["ai_error"] = f"AI 过滤不可用: {e}"

        result["findings"] = [scan_result_to_row(r) for r in raw_results]
        result["_raw_results"] = raw_results

    result["count"] = len(raw_results)
    with TASK_LOCK:
        SCAN_HISTORY.insert(0, result)
    _update_task(
        task,
        stage="done",
        progress=1.0,
        findings=len(raw_results),
        message=(
            f"扫描完成：确认 {len(result.get('confirmed', []))} / "
            f"误报 {len(result.get('false_positives', []))} / "
            f"待复核 {len(result.get('needs_review', []))}"
        ),
        redirect="/",
    )


def _run_scan_crawled_task(task, crawl_id, selected_urls, headers):
    crawl_result = CRAWL_CACHE.pop(crawl_id, None)
    if not crawl_result:
        _update_task(task, stage="error", progress=1.0,
                     error="爬取结果已过期，请重新爬取", message="爬取结果已过期")
        return

    pipeline_result = _create_result(domain=crawl_result.start_url)
    pipeline_result["subdomains"] = []
    pipeline_result["live_hosts"] = selected_urls
    pipeline_result["host_results"] = []

    total = len(selected_urls)
    for i, url in enumerate(selected_urls):
        base = i / max(total, 1)
        step = 1.0 / max(total, 1)
        _update_task(task, stage="scanning", progress=base,
                     message=f"扫描 {i + 1}/{total}: {url}（指纹识别）")
        hr = {"url": url, "findings": [], "confirmed": [], "fp": [], "review": [], "error": None}
        try:
            fingerprint = fingerprint_target(url, headers=headers)
            suggested = suggest_templates(fingerprint.get("technologies", []))
            _update_task(task, progress=base + 0.15 * step,
                         message=f"扫描 {i + 1}/{total}: {url}（Nuclei 扫描中）")

            def on_scan_progress(found, elapsed):
                _update_task(
                    task,
                    stage="scanning",
                    progress=base + step * (0.15 + 0.4 * min(found / 20.0, 1.0)),
                    findings=found,
                    message=f"扫描 {i + 1}/{total}: {url}（已发现 {found} 条，运行 {elapsed}s）",
                )

            raw, _ = run_nuclei_scan(url, suggested_templates=suggested, headers=headers,
                                     progress_cb=on_scan_progress)
            if raw:
                _update_task(task, progress=base + 0.6 * step,
                             message=f"扫描 {i + 1}/{total}: {url}（AI 分析 {len(raw)} 条）")

                def on_ai_progress(done, total_count):
                    _update_task(
                        task,
                        stage="ai_filtering",
                        progress=base + step * (0.6 + 0.35 * (done / max(total_count, 1))),
                        findings=done,
                        message=f"AI 分析 {i + 1}/{total}: {done}/{total_count} 条…",
                    )

                confirmed, fp, review = asyncio.run(
                    filter_results(raw, progress_cb=on_ai_progress)
                )
                hr["findings"] = [scan_result_to_row(r) for r in raw]
                hr["confirmed"] = [scan_result_to_row(r) for r in confirmed]
                hr["fp"] = [scan_result_to_row(r) for r in fp]
                hr["review"] = [scan_result_to_row(r) for r in review]
        except subprocess.TimeoutExpired:
            hr["error"] = "扫描超时"
        except Exception as e:
            hr["error"] = str(e)
        pipeline_result["host_results"].append(hr)

    with TASK_LOCK:
        SCAN_HISTORY.insert(0, pipeline_result)
    _update_task(task, stage="done", progress=1.0,
                 message=f"完成：共扫描 {total} 个 URL", redirect="/")


def _run_pipeline_task(task, domain, headers):
    result = _create_result(domain=domain)
    result["subdomains"] = []
    result["live_hosts"] = []
    result["host_results"] = []

    _update_task(task, stage="scanning", progress=0.02, message="正在枚举子域名…")
    try:
        subs = enumerate_subdomains(domain)
        if not subs:
            subs = enumerate_subdomains_fallback(domain)
        result["subdomains"] = subs
        if not subs:
            result["error"] = "未发现子域名"
        else:
            _update_task(task, stage="scanning", progress=0.08,
                         message=f"发现 {len(subs)} 个子域名，正在探测存活主机…")
            live_lines = check_live_hosts(subs)
            result["live_hosts"] = live_lines

            cfg = get_config()
            max_scan = cfg.get("max_pipeline_hosts", 10)
            targets = live_lines[:max_scan]
            total = len(targets)
            for i, line in enumerate(targets):
                parts = line.split()
                if not parts:
                    continue
                url = parts[0].strip()
                if not url.startswith("http"):
                    url = f"http://{url}"

                base = 0.1 + 0.8 * (i / max(total, 1))
                step = 0.8 / max(total, 1)
                _update_task(task, stage="scanning", progress=base,
                             message=f"扫描 {i + 1}/{total}: {url}（指纹识别）")
                host_result = {"url": url, "findings": [], "confirmed": [],
                               "fp": [], "review": [], "error": None}
                try:
                    _update_task(task, progress=base + 0.15 * step,
                                 message=f"扫描 {i + 1}/{total}: {url}（Nuclei 扫描中）")

                    def on_scan_progress(found, elapsed):
                        _update_task(
                            task,
                            stage="scanning",
                            progress=base + step * (0.15 + 0.4 * min(found / 20.0, 1.0)),
                            findings=found,
                            message=f"扫描 {i + 1}/{total}: {url}（已发现 {found} 条，运行 {elapsed}s）",
                        )

                    raw_results, _ = run_nuclei_scan(url, None, include_demo=False,
                                                     headers=headers if headers else None,
                                                     progress_cb=on_scan_progress)
                    if raw_results:
                        _update_task(task, progress=base + 0.6 * step,
                                     message=f"扫描 {i + 1}/{total}: {url}（AI 分析 {len(raw_results)} 条）")

                        def on_ai_progress(done, total_count):
                            _update_task(
                                task,
                                stage="ai_filtering",
                                progress=base + step * (0.6 + 0.35 * (done / max(total_count, 1))),
                                findings=done,
                                message=f"AI 分析 {i + 1}/{total}: {done}/{total_count} 条…",
                            )

                        confirmed, fp, review = asyncio.run(
                            filter_results(raw_results, progress_cb=on_ai_progress)
                        )
                        host_result["findings"] = [scan_result_to_row(r) for r in raw_results]
                        host_result["confirmed"] = [scan_result_to_row(r) for r in confirmed]
                        host_result["fp"] = [scan_result_to_row(r) for r in fp]
                        host_result["review"] = [scan_result_to_row(r) for r in review]
                except subprocess.TimeoutExpired:
                    host_result["error"] = "扫描超时"
                except Exception as e:
                    host_result["error"] = str(e)
                result["host_results"].append(host_result)
    except Exception as e:
        result["error"] = str(e)

    with TASK_LOCK:
        SCAN_HISTORY.insert(0, result)
    _update_task(task, stage="done", progress=1.0, message="管线扫描完成", redirect="/")


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
    """Handle scan form submission: 后台任务 + 前端轮询进度。"""
    if not target.startswith("http"):
        result = _create_result(target=target)
        result["error"] = "URL must start with http:// or https://"
        with TASK_LOCK:
            SCAN_HISTORY.insert(0, result)
        return templates.TemplateResponse("index.html", {
            "request": request,
            "title": "NucleiAI - AI增强漏洞管理平台",
            "history": SCAN_HISTORY,
            "saved_sessions": list_sessions(),
            "last_target": target,
        })

    custom_headers = []
    if hdr_key.strip():
        custom_headers.append((hdr_key.strip(), hdr_val.strip()))
    headers = build_headers_from_form(cookie=cookie, bearer=bearer,
                                       custom_headers=custom_headers,
                                       session_name=session_name)

    if step == "crawl" or crawl_depth > 0:
        task = _start_task("crawl", _run_crawl_task,
                           args=(target, crawl_depth, max_pages, headers),
                           message="正在启动爬取…")
    else:
        task = _start_task("scan", _run_scan_task,
                           args=(target, headers, use_community),
                           message="正在启动扫描…")

    return templates.TemplateResponse("index.html", {
        "request": request,
        "title": "NucleiAI - 任务进行中",
        "history": SCAN_HISTORY,
        "saved_sessions": list_sessions(),
        "last_target": target,
        "running_task": task,
    })


@app.get("/crawl/{task_id}", response_class=HTMLResponse)
async def crawl_view(request: Request, task_id: str,
                     cookie: str = "", bearer: str = "", session_name: str = ""):
    """渲染爬取结果页（任务完成后由前端跳转到这里）。"""
    task = SCAN_TASKS.get(task_id)
    if not task or task.get("stage") != "done" or not task.get("crawl_view"):
        return HTMLResponse("<h3>爬取任务不存在或尚未完成</h3>", status_code=404)
    view = task["crawl_view"]
    return templates.TemplateResponse("index.html", {
        "request": request,
        "title": "NucleiAI - 爬取结果",
        "history": SCAN_HISTORY,
        "crawl_result": view,
        "cookie": cookie,
        "bearer": bearer,
        "session_name": session_name,
        "saved_sessions": list_sessions(),
        "last_target": view["start_url"],
    })


@app.get("/api/task/{task_id}")
async def task_status(task_id: str):
    """任务进度 JSON，供前端轮询。"""
    task = SCAN_TASKS.get(task_id)
    if not task:
        return JSONResponse({"error": "not found"}, status_code=404)
    return {
        "id": task["id"],
        "stage": task["stage"],
        "progress": task["progress"],
        "message": task["message"],
        "pages": task.get("pages", 0),
        "urls_found": task.get("urls_found", 0),
        "findings": task.get("findings", 0),
        "error": task.get("error"),
        "redirect": task.get("redirect", "/"),
    }


@app.post("/scan-crawled", response_class=HTMLResponse)
async def scan_crawled_urls(request: Request,
                             crawl_id: str = Form(...),
                             selected_urls: list[str] = Form(...),
                             cookie: str = Form(""),
                             bearer: str = Form(""),
                             session_name: str = Form("")):
    """Scan selected URLs from a crawl result（后台任务 + 进度）。"""
    headers = build_headers_from_form(cookie=cookie, bearer=bearer,
                                       session_name=session_name)
    task = _start_task("scan_crawled", _run_scan_crawled_task,
                       args=(crawl_id, selected_urls, headers),
                       message=f"准备扫描 {len(selected_urls)} 个 URL…")
    return templates.TemplateResponse("index.html", {
        "request": request,
        "title": "NucleiAI - 任务进行中",
        "history": SCAN_HISTORY,
        "saved_sessions": list_sessions(),
        "running_task": task,
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
                     if not r.get("ai_verdict", {}).get("is_false_positive", False)
                     and not r.get("ai_verdict", {}).get("needs_review", False)]
    fp_raw = [r for r in raw_results
              if r.get("ai_verdict", {}).get("is_false_positive", False)]
    review_raw = [r for r in raw_results
                  if r.get("ai_verdict", {}).get("needs_review", False)
                  and not r.get("ai_verdict", {}).get("is_false_positive", False)]

    report_data = generate_report_data(raw_results, confirmed_raw, fp_raw, review_raw)
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
    """Full automated pipeline（后台任务 + 进度）。"""
    headers = build_headers_from_form(cookie=cookie, bearer=bearer,
                                       session_name=session_name)
    task = _start_task("pipeline", _run_pipeline_task,
                       args=(domain, headers),
                       message="正在启动资产发现…")
    return templates.TemplateResponse("index.html", {
        "request": request,
        "title": "NucleiAI - 任务进行中",
        "history": SCAN_HISTORY,
        "saved_sessions": list_sessions(),
        "last_target": domain,
        "running_task": task,
    })
