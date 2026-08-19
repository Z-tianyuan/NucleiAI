"""统一 LLM 客户端逻辑测试。"""

import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from core.llm import extract_json, resolve_llm  # noqa: E402


def test_extract_json_from_mixed_text():
    assert extract_json('前面的话 [{"a": 1}, {"a": 2}] 后面的话') == [{"a": 1}, {"a": 2}]
    assert extract_json('```json\n{"grade": "B"}\n```') == {"grade": "B"}
    assert extract_json("没有 json") is None


def test_resolve_llm_prefers_openai_with_key(monkeypatch):
    fake_cfg = {
        "llm_provider": "auto",
        "llm_base_url": "https://api.deepseek.com/v1",
        "llm_model": "deepseek-chat",
        "llm_api_key_env": "NUCLEIAI_LLM_API_KEY",
        "llm_api_key": "",
        "llm_temperature": 0.2,
        "llm_timeout": 120,
        "ollama_host": "http://localhost:11434",
        "ollama_model": "qwen3:8b",
        "ollama_timeout": 300,
    }
    monkeypatch.setattr("core.llm.get_config", lambda: fake_cfg)
    monkeypatch.setenv("NUCLEIAI_LLM_API_KEY", "sk-test")

    llm = resolve_llm()
    assert llm["kind"] == "openai"
    assert llm["model"] == "deepseek-chat"


def test_resolve_llm_falls_back_to_ollama(monkeypatch):
    fake_cfg = {
        "llm_provider": "auto",
        "llm_base_url": "",
        "llm_model": "deepseek-chat",
        "llm_api_key_env": "NUCLEIAI_LLM_API_KEY",
        "llm_api_key": "",
        "llm_temperature": 0.2,
        "llm_timeout": 120,
        "ollama_host": "http://localhost:11434",
        "ollama_model": "qwen3:8b",
        "ollama_timeout": 300,
    }
    monkeypatch.setattr("core.llm.get_config", lambda: fake_cfg)
    monkeypatch.delenv("NUCLEIAI_LLM_API_KEY", raising=False)

    llm = resolve_llm()
    assert llm["kind"] == "ollama"
    assert llm["model"] == "qwen3:8b"
