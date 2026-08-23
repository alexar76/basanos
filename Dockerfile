FROM ghcr.io/astral-sh/uv:0.11.17@sha256:03bdc89bb9798628846e60c3a9ad19006c8c3c724ccd2985a33145c039a0577b AS uv
FROM python:3.12-slim@sha256:dd29372629eeba2dd003fd9e9d35a5b8236c44727875a0364254b5127af88e65
WORKDIR /app
COPY --from=uv /uv /bin/uv
COPY pyproject.toml uv.lock README.md LICENSE ./
COPY agent.py configure_provider.py validate_manifest.py capability.json ./
COPY basanos ./basanos
COPY frontend ./frontend
COPY docs/landing/index.html ./frontend/landing.html
COPY docs/landing/stone.js ./frontend/stone.js
COPY tests/fixtures ./tests/fixtures
RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && uv sync --locked --no-dev --no-editable \
    && rm -rf /root/.cache/uv
RUN mkdir -p /data && chown 65532:65532 /data
ENV PATH="/app/.venv/bin:$PATH" \
    HOST=0.0.0.0 \
    PORT=9470 \
    AIMARKET_PROVIDER_IDENTITY_FILE=/data/provider.key \
    BASANOS_DATA_DIR=/data \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
USER 65532:65532
VOLUME ["/data"]
EXPOSE 9470
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:9470/health', timeout=3).read()"
CMD ["python", "agent.py"]
