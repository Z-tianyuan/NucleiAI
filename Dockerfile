# NucleiAI - AI-enhanced vulnerability management platform
# 用法见 README「Docker 部署」一节。
# 构建参数可覆盖 nuclei / httpx 版本，默认 nuclei v3.8.0、httpx v1.4.0

FROM python:3.11-slim

ARG NUCLEI_VERSION=v3.8.0
ARG HTTPX_VERSION=v1.4.0

WORKDIR /app

# ProjectDiscovery 二进制（linux amd64 静态构建）
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl unzip \
    && curl -sSL "https://github.com/projectdiscovery/nuclei/releases/download/${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION#v}_linux_amd64.zip" -o /tmp/nuclei.zip \
    && unzip -o /tmp/nuclei.zip -d /usr/local/bin/ && rm /tmp/nuclei.zip \
    && curl -sSL "https://github.com/projectdiscovery/httpx/releases/download/${HTTPX_VERSION}/httpx_${HTTPX_VERSION#v}_linux_amd64.zip" -o /tmp/httpx.zip \
    && unzip -o /tmp/httpx.zip -d /usr/local/bin/ && rm /tmp/httpx.zip \
    && apt-get purge -y curl unzip && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# 数据目录（结果/会话/报告），可挂载卷持久化
RUN mkdir -p /app/results /app/sessions /app/reports
VOLUME ["/app/results", "/app/sessions", "/app/reports"]

EXPOSE 8080

# 默认启动 Web 面板；LLM 通过环境变量或 config.local.yaml 配置
CMD ["python", "run.py"]
