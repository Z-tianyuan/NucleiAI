# NucleiAI — AI 增强漏洞管理平台

[![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-green.svg)](https://fastapi.tiangolo.com/)
[![Nuclei](https://img.shields.io/badge/Nuclei-v3.8.0-orange.svg)](https://github.com/projectdiscovery/nuclei)
[![CI](https://img.shields.io/github/actions/workflow/status/Z-tianyuan/NucleiAI/ci.yml?branch=master)](https://github.com/Z-tianyuan/NucleiAI/actions)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

在 [ProjectDiscovery Nuclei](https://github.com/projectdiscovery/nuclei) 扫描引擎之上，集成 **LLM 智能误报过滤**，通过 **Web 面板**可视化呈现，一键生成**中文漏洞报告**。

> 定位：开源的安全工具开发演示项目 + 面试求职作品，展示 安全工具开发 + AI 应用 + 全栈 能力。

## ✨ 核心功能

- **🔍 智能扫描** — Nuclei 引擎 + 20 个自编检测模板（5 技法演示 + 15 漏洞检测）+ 指纹智能选模，可选加载官方社区模板（8000+）
- **🧠 AI 误报过滤** — LLM 批量分析，输出三分类：真实漏洞 / 误报 / 待人工复核；LLM 分析失败时不再默认当作漏洞
- **🛡️ 混合防线** — LLM 语义分析 + 5 条代码层硬规则确定性修正，保证稳态准确率 90%+
- **🔎 指纹识别** — httpx 技术栈探测，自动匹配官方检测模板
- **🕷️ 爬虫 + 会话** — BFS 爬取（robots 尊重/同域限制），Cookie / Bearer / 自定义头，命名会话持久化，支持登录态扫描
- **🌐 资产发现** — crt.sh 子域名枚举 + httpx 存活探测，全自动 pipeline：发现 → 存活 → 扫描 → AI 过滤 → 报告
- **📊 Web 面板** — FastAPI + Jinja2 深色仪表盘，可选访问令牌保护，实时展示判定与置信度
- **📄 中文报告** — LLM 安全摘要 + 严重度分布 + 优先修复建议，一键打印 PDF
- **🔁 扫描对比** — 两次扫描 Diff：已修复 / 新增 / 持续存在
- **⚡ LLM 双后端** — 本地 Ollama（零费用、数据不出本机）或任意 OpenAI 兼容 API（DeepSeek / 火山方舟 / OpenAI），自动切换

## 🏗️ 架构

```
┌───────────────────────────────────────────────────────────┐
│                    Web Dashboard :8080                    │
│        FastAPI + Jinja2 ｜ 可选访问令牌 / 登录页           │
├───────────────────────────────────────────────────────────┤
│  ┌────────┐  ┌──────────────┐  ┌────────────────────────┐ │
│  │ httpx  │  │ Nuclei       │  │ LLM (Ollama / OpenAI)  │ │
│  │ 指纹识别 │  │ 模板扫描引擎  │  │ 批量分析 + 硬规则修正    │ │
│  └───┬────┘  └──────┬───────┘  └───────────┬────────────┘ │
│      │              │                      │              │
│  ┌───┴──────────────┴──────────────────────┴───────────┐  │
│  │ 爬虫 / 会话 / 资产发现 / pipeline                     │  │
│  │ 20 Custom Templates + 可选 Community Templates       │  │
│  └─────────────────────────────────────────────────────┘  │
├───────────────────────────────────────────────────────────┤
│              Target + Vulnerable Server                    │
└───────────────────────────────────────────────────────────┘
```

## 🛠️ 技术栈

| 层 | 技术 | 用途 |
|---|------|------|
| 扫描引擎 | Nuclei v3.8.0 (Go) | YAML 模板漏洞扫描 |
| 指纹识别 | httpx (Go) | 技术栈探测 / 存活检查 |
| AI 推理 | Ollama (qwen3:8b) 或 OpenAI 兼容 API | 误报过滤 + 报告摘要 |
| 后端 | FastAPI (Python) | Web API + 业务逻辑 |
| 前端 | Jinja2 + 原生 CSS | 仪表盘 + 报告渲染 |
| 靶场 | Python http.server | 本地漏洞测试环境 |
| 质量 | pytest + GitHub Actions | 单元测试 + CI |

## 🚀 快速开始

### 环境要求

- Python 3.11+
- Nuclei v3.8+ / httpx（Go 二进制，可用 `nuclei -version` 验证）
- LLM 二选一：
  - **Ollama + qwen3:8b**（本地，推荐演示）：`ollama serve` + `ollama pull qwen3:8b`
  - **OpenAI 兼容 API**（DeepSeek / 火山方舟 / OpenAI）：准备 API Key

### 一键启动（Windows）

```powershell
.\start.bat
```

脚本会自动安装依赖、检查环境、启动本地靶场（127.0.0.1:9999）和 Web 面板（127.0.0.1:8080）。

### 手动启动

```bash
# 1. 安装依赖
pip install -r requirements.txt

# 2. 检查环境（二进制 / LLM / 模板）
python run.py check

# 3. 启动 Web 面板
python run.py
# 或 uvicorn web.app:app --host 127.0.0.1 --port 8080
```

浏览器打开 `http://127.0.0.1:8080`，输入 `http://127.0.0.1:9999` 扫描本地靶场，或输入你拥有授权的目标。

### 配置 LLM

默认 `auto` 模式：配置了 API Key 与 `base_url` 就自动走 OpenAI 兼容接口，否则退回 Ollama。两种方式任选：

**方式一：环境变量（推荐，避免把 Key 写进文件）**

```powershell
$env:NUCLEIAI_LLM_API_KEY = "你的 Key"
$env:NUCLEIAI_LLM_BASE_URL = "https://api.deepseek.com/v1"   # DeepSeek
$env:NUCLEIAI_LLM_MODEL = "deepseek-chat"
python run.py
```

**方式二：`config.local.yaml`（已 gitignore，不进仓库）**

```yaml
llm:
  provider: "auto"     # auto | ollama | openai
  base_url: "https://api.deepseek.com/v1"
  model: "deepseek-chat"
  # API Key 仍建议用环境变量 NUCLEIAI_LLM_API_KEY
```

参考 [config.local.yaml.example](config.local.yaml.example)。

### 面板访问令牌（可选但推荐）

```powershell
$env:NUCLEIAI_AUTH_TOKEN = "你的令牌"
python run.py
```

设置后面板需要登录，未授权请求跳转登录页。也可以写在 `config.local.yaml` 的 `server.auth_token`。

### Docker 部署

```bash
docker build -t nucleiai .
# LLM 走 OpenAI 兼容 API（推荐）
docker run -p 8080:8080 \
  -e NUCLEIAI_LLM_API_KEY=sk-xxx \
  -e NUCLEIAI_LLM_BASE_URL=https://api.deepseek.com/v1 \
  -e NUCLEIAI_AUTH_TOKEN=your-token \
  -v nucleiai_data:/app/results \
  nucleiai
# 或 LLM 走宿主机 Ollama：
# docker run -p 8080:8080 --add-host=host.docker.internal:host-gateway \
#   -e NUCLEIAI_LLM_PROVIDER=ollama \
#   -e OLLAMA_HOST=http://host.docker.internal:11434 \
#   nucleiai
```

> Dockerfile 构建时会从 GitHub Releases 下载 nuclei / httpx 二进制，网络受限环境请先配置代理或改用本机运行。

## 📦 打包分发给别人（免 Python 运行）

Windows 用户可构建一个"双击即用"的免安装包（内含 PyInstaller 打包的 exe + nuclei/httpx 二进制）：

```bash
# 需要 Python 3.12/3.13 + PyInstaller（建议用独立 venv）
python build_package.py
```

产出 `dist/NucleiAI-windows-x64.zip`，解压后：

1. 双击 `NucleiAI-Target.exe` 启动本地漏洞靶场
2. 双击 `NucleiAI.exe` 自动打开 Web 面板
3. 在扫描框输入 `http://127.0.0.1:9999` 即可测试

AI 功能可选：设置 `NUCLEIAI_LLM_API_KEY` / `NUCLEIAI_LLM_BASE_URL`（DeepSeek 等云 API）即可，不配置也能扫描（AI 无法判定的结果标记为"待人工复核"）。可写数据（会话等）保存在 exe 同目录 `data/` 下。

## 📟 命令

```bash
python run.py                # 启动 Web 面板
python run.py check          # 检查二进制 / LLM / 模板
python run.py scan <url>     # 命令行快速扫描 + AI 过滤
```

Web 面板内支持：单目标扫描、爬取 → 勾选 URL 扫描、资产发现（子域名 + 存活）、全自动管线扫描、会话保存、扫描 Diff 对比、中文报告。

## 📁 项目结构

```
NucleiAI/
├── core/
│   ├── config.py            # 配置加载（config.yaml + config.local.yaml + 环境变量）
│   ├── scanner.py           # Nuclei 扫描封装（参数构建 / 模板收集）
│   ├── ai_filter.py         # AI 误报过滤（批量分析 + 硬规则 + 三分类）
│   ├── llm.py               # 统一 LLM 客户端（Ollama / OpenAI 兼容 API）
│   ├── crawler.py           # BFS 爬虫
│   ├── session.py           # 会话管理（Cookie / Bearer / 自定义头）
│   ├── subdomain.py         # crt.sh 子域名枚举 + httpx 存活探测
│   ├── fingerprint.py       # 目标指纹识别
│   ├── pipeline.py          # 自动化 pipeline
│   └── report_generator.py  # 中文报告生成
├── web/
│   ├── app.py               # FastAPI 应用（路由 / 鉴权 / 编排）
│   └── templates/           # 仪表盘 / 报告 / 对比
├── custom-templates/        # 20 个自编 Nuclei 模板
├── test-target/             # 漏洞靶场（14 漏洞 + 6 误报干扰 = 20 端点）
├── tests/                   # pytest 单元测试
├── .github/workflows/       # GitHub Actions CI
├── config.yaml              # 公共配置（可移植默认值）
├── config.local.yaml.example
├── run.py                   # 统一入口
├── start.bat / start.sh     # 一键启动
└── Dockerfile
```

## 📊 AI 准确率（如何验证）

自建漏洞靶场（14 漏洞 + 6 误报干扰 = 20 端点，26 条检测结果）：

| 指标 | 数值 |
|------|:----:|
| 漏洞确认率 | 100% (10/10)（最终一轮） |
| 误报识别率 | 100% (6/6)（最终一轮） |
| 综合准确率 | 100% (16/16)（最终一轮） |
| 全链路耗时 | ~3-5 分钟（瓶颈在 8B 模型推理） |
| 稳态保证 | 混合防线（LLM + 5 条硬规则）≥ 90% |

> 诚实声明：8B 量化模型在同一数据上存在 75%-100% 的波动，硬规则保证确定性场景不错判；以上准确率基于自建靶场，**真实目标的表现需自行评估**，请不要把任何单一工具的判定当作最终结论。

## ✅ 测试

```bash
pip install -r requirements-dev.txt
pytest tests/ -v
```

覆盖：AI 过滤规则 / 配置加载 / 扫描参数 / 爬虫逻辑 / LLM 客户端。CI 在 GitHub Actions 上自动运行（Python 3.11 / 3.12）。

## 🤝 贡献与安全

- 欢迎提 Issue / PR，请先阅读 [CONTRIBUTING.md](CONTRIBUTING.md)
- 发现安全问题请走 [SECURITY.md](SECURITY.md) 中的负责任披露流程

## ⚠️ 免责声明

本工具仅用于**授权安全测试**和教育目的。使用者应确保：

- 仅扫描自己拥有权限的目标（未授权扫描可能触犯法律）
- 漏洞靶场仅监听 `127.0.0.1`，不可对公网暴露
- 遵守当地法律法规

## 📝 License

MIT
