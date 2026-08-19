"""Smoke test: load scan results and run AI filter on them (needs Ollama/LLM + demo_scan.jsonl).

注意：这是一个独立冒烟脚本，不是 pytest 用例。
"""

import json
import asyncio
import sys
import io
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

from core.ai_filter import filter_results


async def main():
    results_path = Path(__file__).resolve().parent.parent / "results" / "demo_scan.jsonl"
    results = []
    with open(results_path, encoding="utf-8") as f:
        for line in f:
            if line.strip():
                results.append(json.loads(line))

    print(f"Loaded {len(results)} scan results\n")

    confirmed, fps, review = await filter_results(results)

    print(f"=== False Positives ({len(fps)}) ===")
    for r in fps:
        name = r.get("info", {}).get("name", "Unknown")
        verdict = r.get("ai_verdict", {})
        print(f"  [{verdict.get('finding_type', '?')}] {name}")
        print(f"  Reason: {verdict.get('reason', 'N/A')} (confidence: {verdict.get('confidence', 0):.0%})")
        print()

    print(f"\n=== Confirmed ({len(confirmed)}) ===")
    for r in confirmed:
        name = r.get("info", {}).get("name", "Unknown")
        verdict = r.get("ai_verdict", {})
        print(f"  [{verdict.get('finding_type', '?')}] {name}")
        print(f"  Reason: {verdict.get('reason', 'N/A')} (confidence: {verdict.get('confidence', 0):.0%})")
        print()

    if review:
        print(f"\n=== Needs Review ({len(review)}) ===")
        for r in review:
            name = r.get("info", {}).get("name", "Unknown")
            verdict = r.get("ai_verdict", {})
            print(f"  [{verdict.get('finding_type', '?')}] {name}")
            print(f"  Reason: {verdict.get('reason', 'N/A')} (confidence: {verdict.get('confidence', 0):.0%})")
            print()


if __name__ == "__main__":
    asyncio.run(main())
