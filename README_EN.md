# NucleiAI — AI-Enhanced Vulnerability Management Platform

[![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-green.svg)](https://fastapi.tiangolo.com/)
[![Nuclei](https://img.shields.io/badge/Nuclei-v3.8.0-orange.svg)](https://github.com/projectdiscovery/nuclei)
[![Ollama](https://img.shields.io/badge/Ollama-qwen3:8b-purple.svg)](https://ollama.com/)

An intelligent false-positive filter and report generator built on top of [ProjectDiscovery Nuclei](https://github.com/projectdiscovery/nuclei). Uses **local LLMs** for semantic analysis, provides a **web dashboard** for visualization, and generates **security reports** in one click.

> Built as a portfolio project demonstrating security tool development + AI integration + full-stack engineering.

## Features

- **Smart Scanning** — Nuclei engine + 20 custom templates (5 technique demos + 15 vulnerability detection) + fingerprint-based template selection
- **AI False-Positive Filtering** — Ollama local LLM batch analysis with three-category classification (tech/vuln/exposure)
- **Hybrid Defense** — 5 code-level hard rules auto-correct AI misjudgments, ensuring 90%+ steady-state accuracy
- **Web Dashboard** — FastAPI + Jinja2 dark-themed dashboard with real-time verdicts and confidence scores
- **Chinese Security Reports** — LLM-generated executive summary + severity distribution + prioritized remediation
- **Fingerprint Recognition** — httpx technology stack detection for smart template selection
- **Batch Analysis** — Single LLM inference call processes all findings, ~1 minute full pipeline

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                    Web Dashboard                     │
│              FastAPI + Jinja2 :8000                  │
├─────────────────────────────────────────────────────┤
│  ┌─────────┐  ┌──────────────┐  ┌────────────────┐  │
│  │ httpx   │  │ Nuclei       │  │ Ollama         │  │
│  │ Finger-  │  │ Template     │  │ Batch AI       │  │
│  │ printing │  │ Engine       │  │ Analysis       │  │
│  └────┬────┘  └──────┬───────┘  └───────┬────────┘  │
│       │              │                   │           │
│  ┌────┴──────────────┴───────────────────┴────────┐  │
│  │              20 Custom Templates                │  │
│  │  5× Demo + 15× Vuln (OWASP Top 10 coverage)     │  │
│  └─────────────────────────────────────────────────┘  │
├─────────────────────────────────────────────────────┤
│              Target + Vulnerable Server              │
└─────────────────────────────────────────────────────┘
```

## Tech Stack

| Layer | Technology | Purpose |
|-------|-----------|---------|
| Scanner | Nuclei v3.8.0 (Go) | YAML template-based vulnerability scanning |
| Fingerprinting | httpx (Go) | Technology stack detection |
| AI Inference | Ollama + qwen3:8b | False-positive filtering + report summaries |
| Backend | FastAPI (Python) | Web API + business logic |
| Frontend | Jinja2 + vanilla CSS | Dashboard + report rendering |
| Test Target | Python http.server | Local vulnerable test environment |

## Quick Start

### Prerequisites

- Python 3.11+
- Nuclei v3.8+ / httpx (Go binaries)
- Ollama + qwen3:8b model

### Installation

```bash
git clone https://github.com/Z-tianyuan/NucleiAI.git
cd NucleiAI

pip install -r requirements.txt

# Verify binaries
nuclei -version
httpx -version

# Start Ollama (if not running)
ollama serve

# Pull model
ollama pull qwen3:8b
```

### Launch

```bash
# 1. Start vulnerable test server (port 9999)
cd test-target && python vuln_server.py 9999 &

# 2. Start web dashboard (port 8000)
cd .. && python -m uvicorn web.app:app --host 127.0.0.1 --port 8000
```

Open `http://127.0.0.1:8000`, enter `http://127.0.0.1:9999` to scan.

## Project Structure

```
NucleiAI/
├── core/
│   ├── ai_filter.py         # AI false-positive filter (batch analysis)
│   ├── report_generator.py  # Chinese report generation (LLM summary)
│   ├── fingerprint.py       # Target fingerprinting (httpx)
│   └── scanner.py           # Nuclei scan wrapper
├── web/
│   ├── app.py               # FastAPI app + routes
│   └── templates/
│       ├── index.html       # Dashboard
│       ├── report.html      # Report template
│       └── compare.html     # Scan diff view
├── custom-templates/        # 20 custom Nuclei templates
│   ├── 01-05-*.yaml         # Technique demos (word/regex/status/dsl/multi-path)
│   └── vuln-*.yaml          # Vulnerability detection (XSS/SQLi/SSRF/CORS/etc.)
├── test-target/
│   └── vuln_server.py       # Test target (14 vulns + 6 FP traps = 20 endpoints)
├── docs/
│   └── 面试话术.md           # Interview preparation (Chinese)
├── config.yaml
├── requirements.txt
├── README.md
└── README_EN.md
```

## AI Accuracy

Tested on self-built vulnerable server (14 real vulns + 6 FP traps = 20 endpoints, 26 findings):

| Metric | Value |
|--------|:-----:|
| Vulnerability Detection Rate | 100% |
| False Positive Recognition Rate | 100% |
| Overall Accuracy | 100% (16/16 verified) |
| Scan Duration | ~3-5 min |
| Hybrid Defense | AI batch analysis + 5 hard rules |

> Accuracy fluctuates on 8B quantized models (75%-100% between runs). The hybrid defense design ensures 90%+ steady-state accuracy.

## Key Design Decisions

### Why local LLM instead of cloud API?

- **Zero API cost** — suitable for continuous scanning
- **Data privacy** — scan results may contain sensitive info; never leaves the machine
- **Graceful degradation** — scanning still works (without AI) when Ollama is unavailable

### Why hybrid defense instead of pure AI?

8B quantized models have inherent consistency issues. Hard rules handle **deterministic cases** (HTML entity encoding = escaped, internal redirects = safe) while AI handles **semantic understanding** (tutorial pages vs. real exploits). Combined approach guarantees reliability.

### Why batch analysis?

Single LLM call processes all findings — 5x faster than sequential calls. Bonus: LLM sees full context, producing more accurate relative judgments.

## Disclaimer

This tool is for **authorized security testing** and educational purposes only. Users must:
- Only scan targets they own or have permission to test
- Keep the vulnerable server bound to `127.0.0.1` only
- Comply with local laws and regulations

## License

MIT
