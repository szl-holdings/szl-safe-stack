FROM python:3.12.14-slim@sha256:2f17fc044b579bab302c2e8054d3a686e2cb9a83de48e70534b94cd8ebbe06a9

LABEL org.opencontainers.image.title="SZL Frontier Evidence Gateway" \
      org.opencontainers.image.version="0.2.1" \
      org.opencontainers.image.description="Fail-closed local software-evidence classifier and receipt ledger"

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    SZL_GATEWAY_BIND=0.0.0.0 SZL_GATEWAY_DB=/data/frontier-receipts.sqlite3
WORKDIR /app
RUN groupadd --system gateway && useradd --system --gid gateway --home-dir /nonexistent gateway \
    && mkdir /data && chown gateway:gateway /data
COPY --chown=gateway:gateway frontier_gateway /app/frontier_gateway
USER gateway:gateway
EXPOSE 8787
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD ["python", "-m", "frontier_gateway", "self-check"]
ENTRYPOINT ["python", "-m", "frontier_gateway"]
CMD ["serve"]
