"""AI 误报过滤核心逻辑测试（不依赖真实 LLM）。"""

import asyncio
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from core.ai_filter import (  # noqa: E402
    _debug_is_disabled,
    _has_only_escaped_xss,
    _is_git_text_mention,
    _is_internal_redirect,
    filter_results,
)


def test_escaped_xss_detection():
    assert _has_only_escaped_xss("<p>&lt;script&gt;alert(1)&lt;/script&gt;</p>")
    # 真实未转义的 script 不算"仅转义"
    assert not _has_only_escaped_xss("<script>alert(1)</script>")
    assert not _has_only_escaped_xss("")


def test_internal_redirect():
    assert _is_internal_redirect("HTTP/1.1 302 Found\r\nLocation: /login", "example.com")
    assert _is_internal_redirect("Location: https://sub.example.com/x", "example.com")
    assert not _is_internal_redirect("Location: https://evil.com/x", "example.com")
    assert not _is_internal_redirect("")


def test_debug_disabled():
    assert _debug_is_disabled("Debug Mode: OFF")
    assert _debug_is_disabled("redacted for production")
    # 真实 debug JSON 不算
    assert not _debug_is_disabled('"python_version": "3.11" "pid": 1234')
    assert not _debug_is_disabled("")


def test_git_text_mention():
    assert _is_git_text_mention("Index of /.git <p>no links</p>")
    assert not _is_git_text_mention('Index of /.git <a href="/.git/config">config</a>')
    assert not _is_git_text_mention("")


def _sample_result(overrides=None):
    r = {
        "info": {"name": "Test Finding", "severity": "medium", "tags": ["vuln"]},
        "matched-at": "http://example.com/x",
        "response": "HTTP/1.1 200 OK\r\n\r\nok",
    }
    r.update(overrides or {})
    return r


def test_filter_results_marks_llm_failure_as_needs_review(monkeypatch):
    """LLM 调用失败时结果必须进入 needs_review，而不是被当作真实漏洞。"""

    async def fake_chat_text(system, user):
        return None  # 模拟 LLM 完全不可用

    async def fake_warmup():
        return None

    monkeypatch.setattr("core.ai_filter.chat_text", fake_chat_text)
    monkeypatch.setattr("core.ai_filter.llm_warmup", fake_warmup)

    confirmed, fps, review = asyncio.run(filter_results([_sample_result()]))

    assert confirmed == []
    assert fps == []
    assert len(review) == 1
    assert review[0]["ai_verdict"]["needs_review"] is True
    assert "人工复核" in review[0]["ai_verdict"]["reason"]


def test_filter_results_hard_rule_escaped_xss_overrides(monkeypatch):
    """即使 LLM 误判为真实漏洞，硬规则也应把转义 XSS 修正为误报。"""

    async def fake_chat_text(system, user):
        return '[{"finding_type": "vuln", "is_false_positive": false, ' \
               '"confidence": 0.9, "reason": "看起来是漏洞"}]'

    async def fake_warmup():
        return None

    monkeypatch.setattr("core.ai_filter.chat_text", fake_chat_text)
    monkeypatch.setattr("core.ai_filter.llm_warmup", fake_warmup)

    result = _sample_result({
        "response": "HTTP/1.1 200 OK\r\n\r\n<p>&lt;script&gt;alert(1)&lt;/script&gt;</p>",
    })
    confirmed, fps, review = asyncio.run(filter_results([result]))

    assert confirmed == []
    assert len(fps) == 1
    assert "[自动修正]" in fps[0]["ai_verdict"]["reason"]
    assert review == []


def test_filter_results_invokes_progress_cb(monkeypatch):
    """每完成一批应回调 progress_cb(done_count, total_count)。"""

    async def fake_chat_text(system, user):
        return '[{"finding_type": "vuln", "is_false_positive": false, ' \
               '"confidence": 0.8, "reason": "ok"}]'

    async def fake_warmup():
        return None

    monkeypatch.setattr("core.ai_filter.chat_text", fake_chat_text)
    monkeypatch.setattr("core.ai_filter.llm_warmup", fake_warmup)

    calls = []
    results = [_sample_result() for _ in range(3)]
    asyncio.run(filter_results(results, progress_cb=lambda d, t: calls.append((d, t))))

    assert calls, "progress_cb 应该至少被调用一次"
    assert calls[-1] == (3, 3)
