FROM python:3.12.14-slim@sha256:2f17fc044b579bab302c2e8054d3a686e2cb9a83de48e70534b94cd8ebbe06a9 AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /build

COPY build-requirements.lock requirements.lock pyproject.toml README.md ./
COPY src ./src

RUN python -m pip install --no-cache-dir --require-hashes --only-binary=:all: -r build-requirements.lock \
    && python -m pip wheel --no-cache-dir --no-deps --no-build-isolation --wheel-dir /wheels .

FROM python:3.12.14-slim@sha256:2f17fc044b579bab302c2e8054d3a686e2cb9a83de48e70534b94cd8ebbe06a9

LABEL org.opencontainers.image.title="safe-qa-service" \
      org.opencontainers.image.version="0.2.1" \
      org.opencontainers.image.description="Fail-closed evidence and AWS provider control plane"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN groupadd --gid 10001 app && useradd --uid 10001 --gid app --no-create-home app

WORKDIR /app

COPY requirements.lock ./
COPY --from=builder /wheels/safe_qa_service-0.2.1-py3-none-any.whl /tmp/safe_qa_service-0.2.1-py3-none-any.whl
RUN python -m pip install --no-cache-dir --require-hashes --only-binary=:all: -r requirements.lock \
    && python -m pip install --no-cache-dir --no-deps /tmp/safe_qa_service-0.2.1-py3-none-any.whl \
    && rm /tmp/safe_qa_service-0.2.1-py3-none-any.whl

COPY db ./db

USER 10001:10001
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health/live', timeout=2)"]

CMD ["uvicorn", "safe_qa_service.app:app", "--host", "0.0.0.0", "--port", "8080", "--no-server-header"]
