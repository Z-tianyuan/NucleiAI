"""Chinese pentest report generator — LLM summary + structured data."""

import json
from datetime import datetime

from core.llm import chat_text, extract_json

SUMMARY_PROMPT = """你是资深渗透测试专家。根据以下漏洞扫描结果，生成一份中文漏洞摘要。

要求：
1. 按严重程度排序（critical > high > medium > low > info）
2. 每个漏洞用一句话概括
3. 给出整体安全评级（A/B/C/D/F）
4. 列出最优先修复的3个问题

扫描结果（JSON）：
{results_json}

返回JSON格式：
{{
  "overall_grade": "A/B/C/D/F",
  "total_vulnerabilities": 数字,
  "severity_counts": {{"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}},
  "top_issues": ["问题1", "问题2", "问题3"],
  "summary": "整体评估简述（中文，100字以内）"
}}"""


def build_summary_input(results: list[dict]) -> str:
    """Build LLM input from scan results for summary generation."""
    simplified = []
    for r in results:
        info = r.get("info", {})
        verdict = r.get("ai_verdict", {})
        simplified.append({
            "name": info.get("name", "Unknown"),
            "severity": info.get("severity", "info"),
            "description": info.get("description", "")[:200],
            "tags": info.get("tags", []),
            "ai_verdict": verdict.get("finding_type", "?"),
            "is_false_positive": verdict.get("is_false_positive", False),
        })
    return SUMMARY_PROMPT.format(results_json=json.dumps(simplified, ensure_ascii=False))


async def generate_llm_summary(results: list[dict]) -> dict:
    """Call LLM to generate a Chinese summary of scan findings."""
    prompt = build_summary_input(results)
    content = await chat_text("你是资深渗透测试专家，只回复JSON格式。", prompt)
    data = extract_json(content)
    if isinstance(data, dict):
        return data
    return _fallback_summary(results)


def _fallback_summary(results: list[dict]) -> dict:
    """Generate a basic summary without LLM."""
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for r in results:
        sev = r.get("info", {}).get("severity", "info")
        if sev in severity_counts:
            severity_counts[sev] += 1

    total = len(results)
    if total == 0:
        return {
            "overall_grade": "A", "total_vulnerabilities": 0,
            "severity_counts": severity_counts,
            "top_issues": [], "summary": "未发现安全漏洞。"
        }

    if severity_counts["critical"] > 0:
        grade = "F"
    elif severity_counts["high"] > 0:
        grade = "D"
    elif severity_counts["medium"] > 0:
        grade = "C"
    elif severity_counts["low"] > 0:
        grade = "B"
    else:
        grade = "A"

    top = sorted(results, key=lambda r: {
        "critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4
    }.get(r.get("info", {}).get("severity", "info"), 99))[:3]
    top_issues = [r.get("info", {}).get("name", "Unknown") for r in top]

    return {
        "overall_grade": grade, "total_vulnerabilities": total,
        "severity_counts": severity_counts, "top_issues": top_issues,
        "summary": f"共发现{total}个问题，建议优先处理高危及以上漏洞。"
    }


def _row(r: dict) -> dict:
    """Convert a raw nuclei result to a flat display row."""
    info = r.get("info", {})
    verdict = r.get("ai_verdict", {})
    return {
        "name": info.get("name", "Unknown"),
        "severity": info.get("severity", "info"),
        "description": info.get("description", ""),
        "tags": ", ".join(info.get("tags", [])),
        "finding_type": verdict.get("finding_type", "?"),
        "is_false_positive": verdict.get("is_false_positive", False),
        "needs_review": verdict.get("needs_review", False),
        "confidence": verdict.get("confidence", 0),
        "reason": verdict.get("reason", ""),
    }


def generate_report_data(results: list[dict], confirmed: list[dict],
                         false_positives: list[dict],
                         needs_review: list[dict] | None = None) -> dict:
    """Generate structured report data for HTML rendering."""
    needs_review = needs_review or []
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

    sorted_confirmed = sorted(
        confirmed, key=lambda r: severity_order.get(
            r.get("info", {}).get("severity", "info"), 99
        )
    )

    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for r in sorted_confirmed:
        sev = r.get("info", {}).get("severity", "info")
        if sev in severity_counts:
            severity_counts[sev] += 1

    return {
        "meta": {
            "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "total_findings": len(results),
            "confirmed": len(confirmed),
            "false_positives": len(false_positives),
            "needs_review": len(needs_review),
        },
        "severity_counts": severity_counts,
        "findings": [_row(r) for r in sorted_confirmed],
        "false_positives": [_row(r) for r in false_positives],
        "needs_review": [_row(r) for r in needs_review],
    }
