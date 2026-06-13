# mcp-armor sidecar image — runs `python -m mcp_armor.sidecar` as a reverse proxy
# in front of any HTTP-transport MCP server (TypeScript, Go, …). See docs/TYPESCRIPT.md.
#
# Build (from repo root):
#   docker build -t mcp-armor-sidecar .
# Run:
#   docker run --rm -p 8000:8000 \
#     -e ARMOR_SESSION_SECRET=$(python -c "import secrets;print(secrets.token_hex(32))") \
#     -e ARMOR_UPSTREAM=http://host.docker.internal:3000 \
#     -v "$PWD/cosai.yaml:/app/cosai.yaml:ro" \
#     mcp-armor-sidecar

# ---- build stage: produce a wheel so the runtime image carries no build toolchain ----
FROM python:3.12-slim AS build
WORKDIR /src
COPY pyproject.toml README.md ./
COPY mcp_armor ./mcp_armor
RUN pip install --no-cache-dir build hatchling \
    && python -m build --wheel --outdir /dist

# ---- runtime stage ----
FROM python:3.12-slim
WORKDIR /app

# Install the built wheel with the sidecar (httpx + uvicorn) and fastapi extras.
# C1: the wheel pins its own dependency bounds; --no-cache-dir keeps the layer lean.
COPY --from=build /dist/*.whl /tmp/
RUN WHEEL="$(ls /tmp/*.whl)" \
    && pip install --no-cache-dir "${WHEEL}[sidecar,fastapi]" \
    && rm -rf /tmp/*.whl

# Run as a non-root user (the sidecar never needs root; least privilege).
RUN useradd --create-home --uid 10001 armor
USER armor

# Container defaults — bind all interfaces inside the container; the host/orchestrator
# controls external exposure. Override at run time as needed.
ENV ARMOR_SIDECAR_HOST=0.0.0.0 \
    ARMOR_SIDECAR_PORT=8000 \
    ARMOR_CONFIG=/app/cosai.yaml \
    ARMOR_UPSTREAM=http://localhost:3000

EXPOSE 8000

# ARMOR_SESSION_SECRET MUST be supplied at run time (the guard refuses to start
# without it). cosai.yaml is expected at /app/cosai.yaml (mount it read-only).
ENTRYPOINT ["python", "-m", "mcp_armor.sidecar"]
