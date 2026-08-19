"""配置加载与路径解析测试。"""

import importlib
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


@pytest.fixture
def fresh_config(tmp_path, monkeypatch):
    """Load core.config with an isolated project root."""
    monkeypatch.setenv("NUCLEIAI_NUCLEI_BIN", "")
    monkeypatch.setenv("NUCLEIAI_HTTPX_BIN", "")
    monkeypatch.setenv("NUCLEIAI_TEMPLATES_DIR", "")
    monkeypatch.setenv("NUCLEIAI_LLM_API_KEY", "")
    monkeypatch.delenv("NUCLEIAI_LLM_PROVIDER", raising=False)

    import core.config as config
    config._CFG = None
    yield config
    config._CFG = None


def test_loads_defaults_without_file(fresh_config, tmp_path):
    config = fresh_config
    config.CONFIG_PATH = tmp_path / "missing.yaml"
    cfg = config.get_config()
    assert cfg["server_host"] == "127.0.0.1"
    assert cfg["ollama_model"] == "qwen3:8b"
    assert cfg["llm_provider"] in ("", "auto")


def test_local_override_wins(fresh_config, tmp_path):
    config = fresh_config
    (tmp_path / "config.yaml").write_text(
        "server:\n  port: 8080\n", encoding="utf-8"
    )
    (tmp_path / "config.local.yaml").write_text(
        "server:\n  port: 9000\n", encoding="utf-8"
    )
    config.CONFIG_PATH = tmp_path / "config.yaml"
    cfg = config.get_config()
    assert cfg["server_port"] == 9000


def test_auth_token_from_env(fresh_config, tmp_path, monkeypatch):
    config = fresh_config
    config.CONFIG_PATH = tmp_path / "missing.yaml"
    monkeypatch.setenv("NUCLEIAI_AUTH_TOKEN", "secret-token")
    cfg = config.get_config()
    assert cfg["auth_token"] == "secret-token"


def test_check_binaries_reports_missing(fresh_config, tmp_path, monkeypatch):
    config = fresh_config
    monkeypatch.setattr(config, "CONFIG_PATH", tmp_path / "missing.yaml")
    monkeypatch.setattr(config, "BASE_DIR", tmp_path)
    # 隔离 home 目录，避免探测到真实机器上的 ~/bin/nuclei.exe
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    missing = config.check_binaries()
    assert "nuclei" in missing
    assert "httpx" in missing
