"""Quick test: load scan results and run AI filter on them."""
import json
import asyncio
import sys
import io
sys.path.insert(0, ".")
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

from core.ai_filter import filter_result

async def main():
    results = []
    with open("results/demo_scan.jsonl", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                results.append(json.loads(line))

    print(f"Loaded {len(results)} scan results\n")

    for i, r in enumerate(results):
        name = r.get("info", {}).get("name", "Unknown")
        tags = r.get("info", {}).get("tags", [])
        matched = r.get("matcher-name", "?")
        print(f"[{i+1}] {name}")
        print(f"    Tags: {tags}")
        print(f"    Matcher: {matched}")
        print(f"    Sending to qwen3...")

        verdict = await filter_result(r)
        ftype = verdict.get("finding_type", "?")
        is_fp = verdict.get("is_false_positive", False)
        confidence = verdict.get("confidence", 0)
        reason = verdict.get("reason", "N/A")

        fp_label = "[MISREPORT]" if is_fp else "[OK]"
        print(f"    Type: {ftype} | Verdict: {fp_label} | Confidence: {confidence:.0%}")
        print(f"    Reason: {reason}")
        print()

asyncio.run(main())
