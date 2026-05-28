# NucleiAI — AI 增强漏洞管理平台

[![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-green.svg)](https://fastapi.tiangolo.com/)
[![Nuclei](https://img.shields.io/badge/Nuclei-v3.8.0-orange.svg)](https://github.com/projectdiscovery/nuclei)
[![Ollama](https://img.shields.io/badge/Ollama-qwen3:8b-purple.svg)](https://ollama.com/)

在 [ProjectDiscovery Nuclei](https://github.com/projectdiscovery/nuclei) 扫描引擎之上，集成**本地大模型**进行智能误报过滤，通过 **Web 面板**可视化呈现，一键生成**中文漏洞报告**。

> 🎯 暑期实习求职作品 —— 展示安全工具开发 + AI 应用 + 全栈能力

## ✨ 核心功能

- **🔍 智能扫描** — Nuclei 引擎 + 20 个自编检测模板（5 技法演示 + 15 漏洞检测）+ 指纹智能选模
- **🧠 AI 误报过滤** — Ollama 本地 LLM 批量分析，技术识别/漏洞利用/配置暴露三步分类
- **🛡️ 规则兜底** — 代码层硬规则自动修正 AI 误判，混合防线保证准确率
- **📊 Web 面板** — FastAPI + Jinja2 深色主题仪表盘，实时展示判定结果与置信度
- **📄 中文报告** — LLM 生成安全摘要 + 严重度分布 + 优先修复建议，一键打印 PDF
- **🔎 指纹识别** — httpx 技术栈探测，自动识别目标使用的框架与版本
- **⚡ 批量分析** — 单次 LLM 推理分析全部结果，全链路 ~1 分钟

## 🏗️ 架构

```
┌─────────────────────────────────────────────────────┐
│                    Web Dashboard                     │
│              FastAPI + Jinja2 :8000                  │
├─────────────────────────────────────────────────────┤
│  ┌─────────┐  ┌──────────────┐  ┌────────────────┐  │
│  │ httpx   │  │ Nuclei       │  │ Ollama         │  │
│  │ 指纹识别 │  │ 模板扫描引擎  │  │ 批量 AI 分析    │  │
│  └────┬────┘  └──────┬───────┘  └───────┬────────┘  │
│       │              │                   │           │
│  ┌────┴──────────────┴───────────────────┴────────┐  │
│  │              20 Custom Templates                │  │
│  │  5× Demo (技法展示) + 15× Vuln (漏洞检测)        │  │
│  └─────────────────────────────────────────────────┘  │
├─────────────────────────────────────────────────────┤
│              Target + Vulnerable Server              │
└─────────────────────────────────────────────────────┘
```

## 🛠️ 技术栈

| 层 | 技术 | 用途 |
|---|------|------|
| 扫描引擎 | Nuclei v3.8.0 (Go) | YAML 模板漏洞扫描 |
| 指纹识别 | httpx (Go) | 技术栈探测 |
| AI 推理 | Ollama + qwen3:8b | 误报过滤 + 报告摘要 |
| 后端 | FastAPI (Python) | Web API + 业务逻辑 |
| 前端 | Jinja2 + 原生 CSS | 仪表盘 + 报告渲染 |
| 靶场 | Python http.server | 本地漏洞测试环境 |

## 🚀 快速开始

### 环境要求

- Python 3.11+
- Nuclei v3.8+ / httpx（Go 二进制）
- Ollama + qwen3:8b 模型

### 安装

```bash
# 克隆项目
git clone https://github.com/Z-tianyuan/NucleiAI.git
cd NucleiAI

# 安装 Python 依赖
pip install -r requirements.txt

# 确保 Nuclei 和 httpx 在 PATH 中
nuclei -version
httpx -version

# 启动 Ollama（如未运行）
ollama serve

# 拉取模型
ollama pull qwen3:8b
```

### 启动

```bash
# 1. 启动漏洞靶场（端口 9999）
cd test-target && python vuln_server.py 9999 &

# 2. 启动 Web 面板（端口 8000）
cd .. && python -m uvicorn web.app:app --host 127.0.0.1 --port 8000
```

打开浏览器访问 `http://127.0.0.1:8000`，输入 `http://127.0.0.1:9999` 开始扫描。

## 📁 项目结构

```
NucleiAI/
├── core/
│   ├── ai_filter.py         # AI 误报过滤（批量分析）
│   ├── report_generator.py  # 中文报告生成（LLM 摘要）
│   ├── fingerprint.py       # 目标指纹识别（httpx）
│   └── scanner.py           # Nuclei 扫描封装
├── web/
│   ├── app.py               # FastAPI 应用 + 路由
│   └── templates/
│       ├── index.html       # 仪表盘
│       └── report.html      # 报告模板
├── custom-templates/        # 20 个自编 Nuclei 模板
│   ├── 01-05-*.yaml         # 技法演示（word/regex/status/dsl/multi-path）
│   └── vuln-*.yaml          # 漏洞检测（XSS/SQLi/SSRF/CORS/信息泄露等）
├── test-target/
│   └── vuln_server.py       # 漏洞靶场（14 漏洞 + 6 误报干扰 = 20 端点）
├── config.yaml
├── requirements.txt
└── README.md
```

## 📊 AI 准确率

使用自建漏洞靶场（14 漏洞 + 6 误报干扰 = 20 端点）测试：

| 指标 | 数值 |
|------|:----:|
| 漏洞确认率 | 100% (10/10) |
| 误报识别率 | 100% (6/6) |
| 综合准确率 | 100% (16/16) |
| 扫描耗时 | ~3-5 分钟 |
| 混合防线 | AI 批量分析 + 5 条硬规则兜底 |

> 准确率在 8B 量化模型上存在波动（75%-100%），混合防线设计可保证稳态 90%+

## ⚠️ 免责声明

本工具仅用于**授权安全测试**和教育目的。使用者应确保：
- 仅扫描自己拥有权限的目标
- 漏洞靶场仅监听 `127.0.0.1`，不可对公网暴露
- 遵守当地法律法规

## 📝 License

MIT
