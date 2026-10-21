# syntax=docker/dockerfile:1
FROM python:3.12-slim AS builder
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv
WORKDIR /src
COPY pyproject.toml uv.lock ./
COPY packages ./packages
COPY eval ./eval
RUN uv sync --frozen --no-dev --package agentshield-gateway

FROM python:3.12-slim
RUN useradd --create-home --uid 10001 agentshield
WORKDIR /app
COPY --from=builder /src/.venv /app/.venv
COPY packages/agentshield-gateway/src ./packages/agentshield-gateway/src
COPY packages/agentshield-core/src ./packages/agentshield-core/src
COPY packages/agentshield-policy/src ./packages/agentshield-policy/src
COPY packages/agentshield-ledger/src ./packages/agentshield-ledger/src
ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONPATH="/app/packages/agentshield-gateway/src:/app/packages/agentshield-core/src:/app/packages/agentshield-policy/src:/app/packages/agentshield-ledger/src" \
    AGENTSHIELD_SHADOW_MODE=false
USER 10001
EXPOSE 8080
CMD ["python", "-m", "uvicorn", "agentshield_gateway.serve:app", "--factory", "--host", "0.0.0.0", "--port", "8080"]
