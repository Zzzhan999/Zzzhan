# Agent2 服务器运营镜像 —— 资产自动发现 + 漏洞验证 + 定时调度
# 零第三方依赖（纯 Python 标准库），无需 pip install
FROM python:3.11-slim

LABEL maintainer="agent2" description="Asset discovery & vulnerability verification service"

WORKDIR /app

# 拷贝代码（data 目录由 volume 挂载，见 .dockerignore）
COPY . /app

# 数据目录（assets.db / scope.json / jobs.json / reports / exports / logs）
RUN mkdir -p /app/data/reports /app/data/exports /app/data/logs \
    && chmod +x /app/main.py

EXPOSE 8000

# 默认启动服务器模式；环境变量可覆盖（见 docker-compose.yml）
ENV AGENT2_TOKEN="" \
    AGENT2_VULN_DB="" \
    AGENT2_JOBS=/app/data/jobs.json \
    AGENT2_LOG_LEVEL=info

CMD ["sh", "-c", "python main.py serve --host 0.0.0.0 --port 8000 \
  --token \"$AGENT2_TOKEN\" \
  --jobs \"$AGENT2_JOBS\" \
  --vuln-db \"$AGENT2_VULN_DB\" \
  --log-dir /app/data/logs \
  --log-level \"$AGENT2_LOG_LEVEL\""]
