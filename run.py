"""NucleiAI — AI-enhanced vulnerability management platform.

Usage:
    python run.py                  Start web dashboard
    python run.py check            Check environment (binaries, Ollama)
    python run.py scan <target>    Quick scan from command line
"""

import sys
import os
from pathlib import Path

# Ensure project root is on sys.path
BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR))


def cmd_check():
    """Check that all dependencies are available."""
    print("=" * 50)
    print("  NucleiAI — Environment Check")
    print("=" * 50)

    from core.config import get_config, check_binaries

    cfg = get_config()

    # Binary checks
    missing = check_binaries()
    if missing:
        print(f"\n  MISSING: {', '.join(missing)}")
        print("  Install with: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")
        print("                go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest")
        print("  Or set paths in config.yaml")
    else:
        print(f"\n  nuclei : {cfg['nuclei_binary']}")
        print(f"  httpx  : {cfg['httpx_binary']}")

    # Templates check
    tmpl_dir = cfg.get("templates_dir", "")
    custom_dir = BASE_DIR / "custom-templates"
    if tmpl_dir:
        print(f"  templates (community): {tmpl_dir}")
    else:
        print(f"  templates (community): not configured — using bundled templates only")
    print(f"  templates (custom)   : {custom_dir} ({len(list(custom_dir.glob('*.yaml')))} files)")

    # Ollama check
    import httpx
    try:
        resp = httpx.get(f"{cfg['ollama_host']}/api/tags", timeout=10)
        if resp.status_code == 200:
            models = [m["name"] for m in resp.json().get("models", [])]
            print(f"\n  Ollama: connected ({cfg['ollama_host']})")
            print(f"  Models: {', '.join(models[:8])}{'...' if len(models) > 8 else ''}")
            if cfg["ollama_model"] in models:
                print(f"  '{cfg['ollama_model']}' available ✓")
            else:
                print(f"  '{cfg['ollama_model']}' NOT found — run: ollama pull {cfg['ollama_model']}")
        else:
            print(f"\n  Ollama: {cfg['ollama_host']} returned {resp.status_code}")
    except Exception:
        print(f"\n  Ollama: NOT reachable at {cfg['ollama_host']}")
        print("  Start with: ollama serve")
        print("  Pull model: ollama pull qwen3:8b")

    # Proxy
    proxy = cfg.get("proxy", "")
    print(f"\n  Proxy: {'enabled — ' + proxy if proxy else 'disabled'}")

    print("\n" + "=" * 50)


def cmd_scan(target: str):
    """Run a quick command-line scan."""
    from core.scanner import run_scan, collect_templates
    from core.fingerprint import fingerprint_target, suggest_templates

    print(f"Scanning {target}...\n")

    # Fingerprint
    suggested = []
    try:
        fp = fingerprint_target(target)
        print(f"  Status: {fp['status_code']} | Server: {fp['web_server']} | Title: {fp['title']}")
        if fp["technologies"]:
            print(f"  Tech: {', '.join(fp['technologies'])}")
            suggested = suggest_templates(fp["technologies"])
    except Exception as e:
        print(f"  Fingerprint failed: {e}")

    # Collect templates + run scan
    template_list = collect_templates(include_demo=False, suggested=suggested)
    print(f"  Templates loaded: {len(template_list)} entries")
    results = run_scan(target, templates=template_list,
                       severity="critical,high,medium,low", timeout=300)

    if not results:
        print("\n  No findings.")
        return

    # AI filter
    import asyncio
    from core.ai_filter import filter_results

    confirmed, fps = asyncio.run(filter_results(results))

    print(f"\n  Total findings : {len(results)}")
    print(f"  Confirmed      : {len(confirmed)}")
    print(f"  False positives: {len(fps)}")
    print()

    for r in confirmed:
        info = r.get("info", {})
        verdict = r.get("ai_verdict", {})
        sev = info.get("severity", "info")
        print(f"  [{sev.upper()}] {info.get('name')}")
        print(f"         {verdict.get('reason', '')}")
        print()


def cmd_serve():
    """Start the web dashboard."""
    from core.config import get_config, check_binaries

    cfg = get_config()
    host = cfg["server_host"]
    port = cfg["server_port"]

    # Pre-flight check
    missing = check_binaries()
    if missing:
        print(f"[warning] Missing binaries: {', '.join(missing)}")
        print("          Scanning will fail. Set paths in config.yaml and retry.")
        print()

    import uvicorn
    print(f"Starting NucleiAI at http://{host}:{port}")
    uvicorn.run("web.app:app", host=host, port=port, reload=False)


def main():
    if len(sys.argv) < 2:
        cmd_serve()
    elif sys.argv[1] == "check":
        cmd_check()
    elif sys.argv[1] == "scan" and len(sys.argv) >= 3:
        cmd_scan(sys.argv[2])
    elif sys.argv[1] in ("-h", "--help", "help"):
        print(__doc__)
    else:
        print(f"Unknown command: {sys.argv[1]}")
        print(__doc__)
        sys.exit(1)


if __name__ == "__main__":
    main()
