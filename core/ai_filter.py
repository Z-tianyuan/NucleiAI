"""LLM-powered false positive filter for nuclei scan results."""

import json

from core.llm import chat_text, extract_json, warmup as llm_warmup

SYSTEM_PROMPT = """你是资深渗透测试工程师，负责审核自动化扫描器的每条发现。

扫描结果分三类，每一类的判定标准不同：

1. 【技术识别类】(tags 含 tech/discovery/detect)
   - 识别目标使用了什么技术栈，不是漏洞
   - 只要响应内容确实包含对应技术特征，就不是误报

2. 【漏洞利用类】(tags 含 vuln/cve/rce/sqli/xss 等)
   - 判断漏洞是否被成功验证
   - 误报场景（重要）：
     a) 页面是安全教程/博客文章（标题含"教程""入门""blog""tutorial"），代码标签出现在教学示例中而非用户输入回显
     b) 匹配到的只是错误页面、默认代码、不相关文本
     c) 用户输入已被 HTML 实体编码（如 &lt;script&gt;），没有真正的脚本执行点

3. 【配置暴露类】(tags 含 exposure/misconfig)
   - 检测敏感文件/面板/API是否对外暴露
   - 误报场景：
     a) 页面是通用错误页，仅以文字提及错误类型（如"如遇 Traceback 请联系管理员"），未包含实际堆栈、文件路径、连接串
     b) 返回的是登录页、404、或明确标注"已关闭""redacted""not available"

输出 JSON 数组，每个元素四个字段：
- finding_type: "vuln" | "tech" | "exposure"
- is_false_positive: true 表示误报，false 表示真实漏洞
- confidence: 0.0-1.0
- reason: 简短中文理由，不超过40字

只输出 JSON 数组，不要任何其他内容。"""


BATCH_PROMPT = """分析以下 {count} 条扫描结果，判断每条是否为误报。

{items}

输出恰好 {count} 个 JSON 对象的数组，不要省略任何一条：
[
  {{"finding_type": "vuln", "is_false_positive": false, "confidence": 0.90, "reason": "理由"}},
  {{"finding_type": "exposure", "is_false_positive": true, "confidence": 0.85, "reason": "理由"}}
]
仅输出 JSON 数组，不要其他内容。"""


def _build_batch_prompt(items: str, count: int) -> str:
    """Build batch prompt safely, avoiding .format() issues with braces in response content."""
    return f"""分析以下 {count} 条扫描结果，判断每条是否为误报。

{items}

输出恰好 {count} 个 JSON 对象的数组，不要省略任何一条：
[
  {{"finding_type": "vuln", "is_false_positive": false, "confidence": 0.90, "reason": "理由"}},
  {{"finding_type": "exposure", "is_false_positive": true, "confidence": 0.85, "reason": "理由"}}
]
仅输出 JSON 数组，不要其他内容。"""


def _summarize_result(result: dict, index: int) -> str:
    """Summarize one scan result for the batch prompt."""
    info = result.get("info", {})
    request = result.get("request", "")
    response = result.get("response", "")
    matched = result.get("matched-at", "")

    response_preview = ""
    if response:
        parts = response.split("\r\n\r\n", 1)
        headers = parts[0][:200]
        body = parts[1][:600] if len(parts) > 1 else ""
        response_preview = f"{headers}\n\n--- response body ---\n{body}"

    return f"""--- 第{index + 1}条 ---
URL路径: {(matched or 'N/A')[:200]}
名称: {info.get('name', 'Unknown')}
标签: {', '.join(info.get('tags', []))}
严重度: {info.get('severity', 'info')}
描述: {info.get('description', 'N/A')[:200]}
请求: {(request or 'N/A')[:300]}
响应: {response_preview}"""


BATCH_SIZE = 5  # Balance speed and accuracy for 8B model


async def filter_results(results: list[dict], timeout: int = 300) -> tuple[list[dict], list[dict], list[dict]]:
    """Analyse scan results in small batches.

    Returns (confirmed, false_positives, needs_review):
    - confirmed:      LLM (or hard rules) 判定为真实漏洞/信息
    - false_positives: LLM (或硬规则) 判定为误报
    - needs_review:   LLM 分析失败、无法给出判定，必须人工复核
    """
    if not results:
        return [], [], []

    # Warmup: ensure model is loaded before timed batches
    await llm_warmup()

    all_verdicts = []
    for batch_start in range(0, len(results), BATCH_SIZE):
        batch = results[batch_start:batch_start + BATCH_SIZE]
        verdicts = await _process_batch(batch, batch_start)
        all_verdicts.extend(verdicts)

    confirmed = []
    false_positives = []
    needs_review = []
    for result, verdict in zip(results, all_verdicts):
        # Hard-rule 1: tech detections are never false positives
        if verdict.get("finding_type") == "tech" and verdict.get("is_false_positive"):
            verdict["is_false_positive"] = False
            verdict["reason"] = "[自动修正] 技术识别类结果不标记为误报"

        # Hard-rule 2: response body has only HTML-escaped XSS payloads -> FP
        if not verdict.get("is_false_positive"):
            resp = (result.get("response") or "")
            body = resp.split("\r\n\r\n", 1)[-1] if "\r\n\r\n" in resp else ""
            if _has_only_escaped_xss(body):
                verdict["is_false_positive"] = True
                verdict["confidence"] = 0.95
                verdict["reason"] = "[自动修正] 响应中脚本标签已被HTML实体编码，不存在XSS执行点"

        # Hard-rule 3: redirect target is internal (same domain) -> safe, not true open redirect
        if not verdict.get("is_false_positive"):
            resp = (result.get("response") or "")
            headers = resp.split("\r\n\r\n")[0] if "\r\n\r\n" in resp else ""
            # Extract target host from result
            target_host = ""
            for field in ["host", "matched-at", "url"]:
                val = result.get(field, "")
                if val:
                    from urllib.parse import urlparse as _up
                    parsed_url = _up(val if "://" in val else f"http://{val}")
                    if parsed_url.hostname:
                        target_host = parsed_url.hostname
                        break
            if _is_internal_redirect(headers, target_host):
                verdict["is_false_positive"] = True
                verdict["confidence"] = 0.95
                verdict["reason"] = "[自动修正] 重定向目标为同一域名，非开放重定向"

        # Hard-rule 4: page says debug mode is OFF or info is redacted -> FP
        if not verdict.get("is_false_positive"):
            resp = (result.get("response") or "")
            body = resp.split("\r\n\r\n", 1)[-1] if "\r\n\r\n" in resp else ""
            if _debug_is_disabled(body):
                verdict["is_false_positive"] = True
                verdict["confidence"] = 0.95
                verdict["reason"] = "[自动修正] 调试模式已关闭，敏感信息已隐藏"

        # Hard-rule 5: git mention in text vs actual directory listing -> FP
        if not verdict.get("is_false_positive"):
            resp = (result.get("response") or "")
            body = resp.split("\r\n\r\n", 1)[-1] if "\r\n\r\n" in resp else ""
            if _is_git_text_mention(body):
                verdict["is_false_positive"] = True
                verdict["confidence"] = 0.95
                verdict["reason"] = "[自动修正] 仅在文字中提及git，未暴露实际仓库文件"

        result["ai_verdict"] = verdict
        if verdict.get("is_false_positive"):
            false_positives.append(result)
        elif verdict.get("needs_review"):
            needs_review.append(result)
        else:
            confirmed.append(result)

    return confirmed, false_positives, needs_review


def _has_only_escaped_xss(body: str) -> bool:
    """Check if body contains XSS keywords only in HTML-escaped form."""
    if not body:
        return False
    if "<script>" in body.lower() or "<script " in body.lower():
        return False
    return "&lt;script&gt;" in body.lower()


def _is_internal_redirect(headers: str, target_host: str = "") -> bool:
    """Check if redirect Location stays within the same domain."""
    if not headers:
        return False
    for line in headers.split("\r\n"):
        if line.lower().startswith("location:"):
            target = line.split(":", 1)[1].strip()
            # Case 1: relative path like /docs or /login
            if target.startswith("/"):
                return True
            # Case 2: absolute URL but same domain (keep params, just rewrite URL)
            if target.startswith("http") and target_host:
                from urllib.parse import urlparse
                parsed = urlparse(target)
                if parsed.hostname == target_host or parsed.hostname.endswith("." + target_host):
                    return True
    return False


def _debug_is_disabled(body: str) -> bool:
    """Check if page explicitly says debug mode is off or info is redacted."""
    if not body:
        return False
    body_lower = body.lower()
    has_off = "debug mode: off" in body_lower or "debug mode:off" in body_lower
    has_redacted = "redacted" in body_lower or "not available in production" in body_lower
    has_real_info = '"python_version"' in body and '"pid"' in body  # real debug JSON
    return (has_off or has_redacted) and not has_real_info


def _is_git_text_mention(body: str) -> bool:
    """Check if page only mentions git in text, not showing actual directory listing."""
    if not body or "Index of /.git" not in body:
        return False
    # Real git listing: has <a href> links to git metadata files
    git_files = ["href=\"/.git/config", "href=\"/.git/HEAD", "href=\"/.git/logs",
                 "href=\"config\"", "href=\"HEAD\"", "href=\"logs/\"", "href=\"refs/\""]
    has_file_links = any(f in body for f in git_files)
    return not has_file_links


async def _process_batch(batch: list[dict], offset: int) -> list[dict]:
    """Process a single batch of up to BATCH_SIZE results."""
    items = "\n\n".join(_summarize_result(r, offset + i) for i, r in enumerate(batch))
    user_prompt = _build_batch_prompt(items, len(batch))

    verdicts = await _call_ollama(user_prompt)

    while len(verdicts) < len(batch):
        verdicts.append({"finding_type": "unknown", "is_false_positive": False,
                         "confidence": 0.0, "reason": "LLM分析失败，请人工复核",
                         "needs_review": True})
    return verdicts[:len(batch)]


async def _call_ollama(prompt: str) -> list[dict]:
    """Call the active LLM backend and parse a JSON array of verdicts."""
    content = await chat_text(SYSTEM_PROMPT, prompt)
    data = extract_json(content)
    if isinstance(data, list):
        return data
    return []
