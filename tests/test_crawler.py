"""爬虫纯逻辑测试。"""

import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from core.crawler import (  # noqa: E402
    _extract_forms,
    _extract_links,
    _is_page_like,
    _normalize_url,
    _same_domain,
)


def test_normalize_url():
    assert _normalize_url("https://Example.com:443/a#frag") == "https://example.com/a"
    assert _normalize_url("http://example.com:80/") == "http://example.com/"


def test_same_domain():
    assert _same_domain("http://a.com/x", "https://a.com/y")
    assert not _same_domain("http://a.com/x", "http://b.com/y")


def test_is_page_like():
    assert _is_page_like("http://a.com/docs")
    assert not _is_page_like("http://a.com/img.png")
    assert not _is_page_like("http://a.com/style.css")
    assert not _is_page_like("ftp://a.com/x")


def test_extract_links():
    html = '<a href="/about">关于</a><a href="https://x.com/">外链</a><a href="#top">锚点</a>'
    links = _extract_links(html, "http://a.com/")
    assert "http://a.com/about" in links
    assert "https://x.com/" in links
    assert not any(l.startswith("#") for l in links)


def test_extract_forms():
    html = (
        '<form action="/login" method="post">'
        '<input name="username"><input type="password" name="password">'
        '</form>'
    )
    forms = _extract_forms(html, "http://a.com/")
    assert len(forms) == 1
    assert forms[0]["action"] == "http://a.com/login"
    assert forms[0]["method"] == "POST"
    assert forms[0]["inputs"] == ["username", "password"]
