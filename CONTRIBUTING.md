# 贡献指南

感谢你对 NucleiAI 感兴趣！本项目定位为安全工具开发演示项目，同时也欢迎社区贡献让它更实用。

## 快速开始

```bash
git clone https://github.com/Z-tianyuan/NucleiAI.git
cd NucleiAI
pip install -r requirements-dev.txt
pytest tests/ -v          # 确保全部通过
```

## 提 Issue

请使用模板：Bug 报告 或 功能建议。至少包含：

- 复现步骤（Bug）
- 期望行为 vs 实际行为
- 环境信息（OS / Python / Nuclei / LLM 后端）

## 提 PR

1. 从 `master` 拉新分支，命名建议 `feat/xxx` 或 `fix/xxx`
2. 保持改动聚焦，一次 PR 解决一个问题
3. 新增功能尽量带 pytest 测试
4. 通过 `pytest tests/ -v` 后再提交
5. PR 描述说明改动动机与验证方式

## 代码规范

- Python 代码遵循 PEP 8，注释/文档用中文或英文皆可，保持一致性
- 不提交任何 API Key、Cookie、扫描结果等敏感数据
- 不提交机器相关绝对路径（本机路径请放 `config.local.yaml`，该文件已被 gitignore）
- 安全相关改动（鉴权、扫描逻辑、LLM 判定）必须附带测试

## 安全相关

如果你发现的是安全问题（而非普通 bug），请**不要**公开提 Issue，走 [SECURITY.md](SECURITY.md) 的负责任披露流程。
