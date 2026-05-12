"""Chinese pentest report generator using LLM."""

import json
from datetime import datetime


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
        simplified.append({
            "name": info.get("name", "Unknown"),
            "severity": info.get("severity", "info"),
            "description": info.get("description", "")[:200],
            "tags": info.get("tags", []),
        })
    return SUMMARY_PROMPT.format(results_json=json.dumps(simplified, ensure_ascii=False))


def generate_report_data(results: list[dict], confirmed: list[dict],
                         false_positives: list[dict]) -> dict:
    """Generate structured report data for PDF rendering."""
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
        },
        "severity_counts": severity_counts,
        "findings": sorted_confirmed,
        "false_positives": false_positives,
    }
