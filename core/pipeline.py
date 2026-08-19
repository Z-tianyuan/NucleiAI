"""Bug bounty pipeline — subdomain discovery → live check → scan → AI filter → report."""

import asyncio
import json
import os
import sys
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.subdomain import enumerate_subdomains, check_live_hosts
from core.scanner import run_scan
from core.ai_filter import filter_results
from core.report_generator import generate_report_data, generate_llm_summary


class BountyPipeline:
    """End-to-end automated bug bounty hunting pipeline."""

    def __init__(self, domain: str, templates_dir: str | None = None,
                 ollama_host: str = "http://localhost:11434", model: str = "qwen3:8b"):
        self.domain = domain
        self.templates_dir = templates_dir
        self.ollama_host = ollama_host
        self.model = model
        self.results = {
            "domain": domain,
            "start_time": datetime.now().isoformat(),
            "subdomains": [],
            "live_hosts": [],
            "scan_results": {},
            "confirmed_vulns": [],
            "false_positives": [],
            "summary": None,
        }

    def discover(self) -> list[str]:
        """Step 1: Discover subdomains."""
        print(f"[*] Enumerating subdomains for {self.domain}...")
        subs = enumerate_subdomains(self.domain)
        self.results["subdomains"] = subs
        print(f"[+] Found {len(subs)} subdomains")
        for s in subs[:20]:
            print(f"    {s}")
        if len(subs) > 20:
            print(f"    ... and {len(subs) - 20} more")
        return subs

    def check_live(self, targets: list[str] | None = None) -> list[str]:
        """Step 2: Check which targets are alive."""
        targets = targets or self.results["subdomains"]
        if not targets:
            print("[!] No targets to check")
            return []

        print(f"\n[*] Checking {len(targets)} targets for live hosts...")
        results = check_live_hosts(targets)
        self.results["live_hosts"] = results
        print(f"[+] {len(results)} live hosts found")
        for r in results[:20]:
            print(f"    {r}")
        return results

    def scan_target(self, target: str,
                    headers: dict[str, str] | None = None) -> list[dict]:
        """Step 3: Scan a single target with nuclei."""
        print(f"\n[*] Scanning {target}...")

        # Collect all templates
        templates = []
        if self.templates_dir and os.path.isdir(self.templates_dir):
            for root, dirs, files in os.walk(self.templates_dir):
                # Skip non-http templates for speed
                if any(skip in root for skip in ["network/", "dns/", "ssl/", "headless/"]):
                    continue
                for f in files:
                    if f.endswith(".yaml") or f.endswith(".yml"):
                        templates.append(os.path.join(root, f))

        # Limit templates for speed (use only info/critical/high first)
        # Actually let nuclei handle template filtering
        results = run_scan(target, severity="info,critical,high,medium,low",
                           timeout=180, headers=headers)
        return results

    async def scan_all_live(self,
                            headers: dict[str, str] | None = None) -> dict:
        """Step 3-4: Scan all live hosts and AI-filter results."""
        live = self.results["live_hosts"]
        if not live:
            return {}

        all_confirmed = []
        all_fp = []
        all_review = []

        for line in live:
            parts = line.split()
            if not parts:
                continue
            url = parts[0].strip()
            if not url.startswith("http"):
                url = f"https://{url}"

            try:
                raw = self.scan_target(url, headers=headers)
                if raw:
                    confirmed, fp, review = await filter_results(raw)
                    all_confirmed.extend(confirmed)
                    all_fp.extend(fp)
                    all_review.extend(review)
                    self.results["scan_results"][url] = {
                        "total": len(raw),
                        "confirmed": len(confirmed),
                        "fp": len(fp),
                        "review": len(review),
                    }
            except Exception as e:
                print(f"[!] Error scanning {url}: {e}")

        self.results["confirmed_vulns"] = all_confirmed
        self.results["false_positives"] = all_fp
        self.results["needs_review"] = all_review
        print(f"\n[+] Pipeline complete: {len(all_confirmed)} confirmed, "
              f"{len(all_fp)} false positives, {len(all_review)} needs review")
        return self.results

    def print_summary(self):
        """Print a human-readable summary."""
        print("\n" + "=" * 60)
        print(f"  Bug Bounty Pipeline Report — {self.domain}")
        print("=" * 60)
        print(f"  Subdomains found:  {len(self.results['subdomains'])}")
        print(f"  Live hosts:        {len(self.results['live_hosts'])}")
        print(f"  Scanned targets:   {len(self.results['scan_results'])}")

        confirmed = self.results["confirmed_vulns"]
        fp = self.results["false_positives"]
        review = self.results.get("needs_review", [])
        print(f"  Confirmed vulns:   {len(confirmed)}")
        print(f"  False positives:   {len(fp)}")
        print(f"  Needs review:      {len(review)}")

        if confirmed:
            print(f"\n  --- Confirmed Findings ---")
            severities = {}
            for r in confirmed:
                sev = r.get("info", {}).get("severity", "info")
                severities[sev] = severities.get(sev, 0) + 1
            for sev, count in sorted(severities.items()):
                print(f"    {sev}: {count}")

            for i, r in enumerate(confirmed[:10]):
                info = r.get("info", {})
                matched = r.get("matched-at", "")
                print(f"\n  [{i + 1}] {info.get('name', '?')}")
                print(f"      Severity: {info.get('severity', '?')}")
                print(f"      URL: {matched}")
                print(f"      AI Confidence: {r.get('ai_verdict', {}).get('confidence', '?')}")
        print("=" * 60)


async def run_pipeline(domain: str, templates_dir: str = "",
                       ollama_host: str = "http://localhost:11434", model: str = "qwen3:8b",
                       skip_discovery: bool = False, skip_live: bool = False,
                       headers: dict[str, str] | None = None):
    """Run the full bug bounty pipeline."""
    pipeline = BountyPipeline(domain, templates_dir, ollama_host, model)

    if not skip_discovery:
        pipeline.discover()

    if not skip_live:
        pipeline.check_live()

    if pipeline.results["live_hosts"]:
        await pipeline.scan_all_live(headers=headers)

    pipeline.print_summary()
    return pipeline.results


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python pipeline.py <domain>")
        print("Example: python pipeline.py example.com")
        sys.exit(1)

    domain = sys.argv[1]
    templates_dir = sys.argv[2] if len(sys.argv) > 2 else ""
    asyncio.run(run_pipeline(domain, templates_dir))
