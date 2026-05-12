"""LLM-powered false positive filter for nuclei scan results."""

import json
import httpx


SYSTEM_PROMPT = """你是网络安全专家，负责判断漏洞扫描结果是否为误报。
分析给定的HTTP请求、响应和匹配内容，判断该漏洞是否真实存在。

返回JSON格式：
{
  "is_false_positive": true/false,
  "confidence": 0.0-1.0,
  "reason": "判断理由（中文，不超过50字）"
}"""


def build_analysis_prompt(result: dict) -> str:
    """Build a prompt for analysing a single scan result."""
    info = result.get("info", {})
    request = result.get("request", "")
    response = result.get("response", "")
    matched = result.get("matched-at", "")

    parts = [
        f"漏洞名称: {info.get('name', 'Unknown')}",
        f"严重程度: {info.get('severity', 'Unknown')}",
        f"描述: {info.get('description', 'N/A')}",
        f"匹配内容: {matched[:500] if matched else 'N/A'}",
        f"HTTP请求 (截断): {request[:800] if request else 'N/A'}",
        f"HTTP响应 (截断): {response[:800] if response else 'N/A'}",
    ]
    return "\n".join(parts)


async def filter_result(result: dict, ollama_host: str = "http://localhost:11434",
                        model: str = "qwen3:8b", timeout: int = 120) -> dict:
    """Analyse a single scan result and return verdict."""
    user_prompt = build_analysis_prompt(result)

    async with httpx.AsyncClient(timeout=timeout) as client:
        resp = await client.post(
            f"{ollama_host}/api/chat",
            json={
                "model": model,
                "messages": [
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": user_prompt},
                ],
                "stream": False,
            },
        )

    if resp.status_code != 200:
        return {"is_false_positive": False, "confidence": 0.0, "reason": "LLM调用失败"}

    content = resp.json()["message"]["content"]
    try:
        # Extract JSON from response
        start = content.find("{")
        end = content.rfind("}") + 1
        if start != -1 and end > start:
            return json.loads(content[start:end])
    except (json.JSONDecodeError, KeyError):
        pass

    return {"is_false_positive": False, "confidence": 0.5, "reason": "无法解析LLM回复"}


async def filter_results(results: list[dict], ollama_host: str = "http://localhost:11434",
                         model: str = "qwen3:8b") -> tuple[list[dict], list[dict]]:
    """Filter scan results, returning (confirmed, false_positives)."""
    confirmed = []
    false_positives = []

    for result in results:
        verdict = await filter_result(result, ollama_host, model)
        if verdict.get("is_false_positive"):
            result["ai_verdict"] = verdict
            false_positives.append(result)
        else:
            result["ai_verdict"] = verdict
            confirmed.append(result)

    return confirmed, false_positives
