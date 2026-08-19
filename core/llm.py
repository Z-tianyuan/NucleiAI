"""Unified LLM client — Ollama (local) or OpenAI-compatible API (DeepSeek/OpenAI/Qwen).

自动选择规则（config.yaml 的 llm.provider）：
- "openai"  : 强制使用 OpenAI 兼容接口（需 llm.base_url + API Key）
- "ollama"  : 强制使用本地 Ollama
- "auto"    : 配置了 API Key 与 base_url 则用 openai，否则退回 ollama
"""

import json
import os

import httpx

from core.config import get_config


def _api_key(cfg: dict) -> str:
    env_name = cfg.get("llm_api_key_env", "NUCLEIAI_LLM_API_KEY")
    return os.environ.get(env_name, "").strip() or str(cfg.get("llm_api_key", "") or "").strip()


def resolve_llm() -> dict:
    """Resolve the active LLM backend from configuration."""
    cfg = get_config()
    provider = str(cfg.get("llm_provider", "auto")).lower()
    api_key = _api_key(cfg)

    if provider == "openai" or (provider == "auto" and api_key and cfg.get("llm_base_url")):
        return {
            "kind": "openai",
            "base_url": str(cfg.get("llm_base_url", "")).rstrip("/"),
            "model": cfg.get("llm_model", "deepseek-chat"),
            "api_key": api_key,
            "temperature": cfg.get("llm_temperature", 0.2),
            "timeout": cfg.get("llm_timeout", 120),
        }
    return {
        "kind": "ollama",
        "host": str(cfg.get("ollama_host", "http://localhost:11434")).rstrip("/"),
        "model": cfg.get("ollama_model", "qwen3:8b"),
        "temperature": cfg.get("llm_temperature", 0.2),
        "timeout": cfg.get("ollama_timeout", 300),
    }


def backend_label() -> str:
    """Human-readable label for the active backend, e.g. 'ollama:qwen3:8b'."""
    llm = resolve_llm()
    return f"{llm['kind']}:{llm['model']}"


async def warmup() -> None:
    """Send a tiny request so the model is loaded before timed batches."""
    try:
        await chat_text("OK", "OK")
    except Exception:
        pass  # Warmup failure is non-fatal


async def chat_text(system: str, user: str) -> str | None:
    """Send a chat request; return the assistant text, or None on failure."""
    llm = resolve_llm()
    try:
        if llm["kind"] == "openai":
            async with httpx.AsyncClient(timeout=llm["timeout"]) as client:
                resp = await client.post(
                    f"{llm['base_url']}/chat/completions",
                    headers={"Authorization": f"Bearer {llm['api_key']}"},
                    json={
                        "model": llm["model"],
                        "messages": [
                            {"role": "system", "content": system},
                            {"role": "user", "content": user},
                        ],
                        "temperature": llm["temperature"],
                        "stream": False,
                    },
                )
            if resp.status_code == 200:
                return resp.json()["choices"][0]["message"]["content"]
        else:
            async with httpx.AsyncClient(timeout=llm["timeout"]) as client:
                resp = await client.post(
                    f"{llm['host']}/api/chat",
                    json={
                        "model": llm["model"],
                        "messages": [
                            {"role": "system", "content": system},
                            {"role": "user", "content": user},
                        ],
                        "options": {"temperature": llm["temperature"]},
                        "stream": False,
                    },
                )
            if resp.status_code == 200:
                return resp.json()["message"]["content"]
    except Exception:
        return None
    return None


def extract_json(text: str):
    """Pull the first JSON value (object or array) out of a model response."""
    if not text:
        return None
    for open_ch, close_ch in (("[", "]"), ("{", "}")):
        start = text.find(open_ch)
        end = text.rfind(close_ch) + 1
        if start != -1 and end > start:
            try:
                return json.loads(text[start:end])
            except json.JSONDecodeError:
                continue
    return None


async def chat_json(system: str, user: str):
    """Send a chat request and parse JSON from the response (object or array)."""
    text = await chat_text(system, user)
    return extract_json(text)
