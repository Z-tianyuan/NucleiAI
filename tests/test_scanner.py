"""扫描参数与模板收集测试（不调用真实 nuclei）。"""

import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from core.scanner import _build_nuclei_args, _is_localhost, collect_templates  # noqa: E402


def test_is_localhost():
    assert _is_localhost("http://127.0.0.1:9999")
    assert _is_localhost("http://localhost/")
    assert _is_localhost("http://192.168.1.1/")
    assert _is_localhost("http://10.0.0.5/")
    assert not _is_localhost("http://example.com/")


def test_build_args_contains_required_flags(monkeypatch):
    fake_cfg = {
        "nuclei_binary": "nuclei",
        "rate_limit": 10,
        "concurrency": 5,
        "proxy": "",
        "scan_delay": 0,
        "scan_retries": 0,
        "severity": "critical,high,medium",
        "user_agents": [],
    }
    monkeypatch.setattr("core.scanner.get_config", lambda: fake_cfg)

    args = _build_nuclei_args("http://example.com", "out.jsonl", ["t.yaml"])
    joined = " ".join(args)
    assert "-jsonl" in joined
    assert "-silent" in joined
    assert "-rate-limit 10" in joined
    assert "-concurrency 5" in joined
    assert "-severity critical,high,medium" in joined
    assert "-output out.jsonl" in joined
    assert "-t t.yaml" in joined


def test_proxy_skipped_for_localhost(monkeypatch):
    fake_cfg = {
        "nuclei_binary": "nuclei",
        "rate_limit": 10,
        "concurrency": 5,
        "proxy": "http://127.0.0.1:7897",
        "scan_delay": 0,
        "scan_retries": 0,
        "severity": "high",
        "user_agents": [],
    }
    monkeypatch.setattr("core.scanner.get_config", lambda: fake_cfg)

    local_args = _build_nuclei_args("http://127.0.0.1:9999", "out.jsonl")
    remote_args = _build_nuclei_args("http://example.com", "out.jsonl")
    assert "-proxy" not in " ".join(local_args)
    assert "-proxy http://127.0.0.1:7897" in " ".join(remote_args)


def test_collect_templates_skips_demo_by_default(monkeypatch, tmp_path):
    custom = tmp_path / "custom-templates"
    custom.mkdir()
    (custom / "01-word.yaml").write_text("id: demo", encoding="utf-8")
    (custom / "vuln-xss.yaml").write_text("id: xss", encoding="utf-8")

    templates = collect_templates(include_demo=False, custom_dir=str(custom))
    names = [Path(t).name for t in templates]
    assert "vuln-xss.yaml" in names
    assert "01-word.yaml" not in names

    templates_demo = collect_templates(include_demo=True, custom_dir=str(custom))
    names_demo = [Path(t).name for t in templates_demo]
    assert "01-word.yaml" in names_demo
