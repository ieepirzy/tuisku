# syntax=docker/dockerfile:1

FROM python:3.12-slim@sha256:aa943ce411423c7582288f18707ff66eddcbaeb510502d747a72aeb34f30d159 AS build
# Keep in step with `version:` of astral-sh/setup-uv in .github/workflows/ci.yml.
COPY --from=ghcr.io/astral-sh/uv:0.11.32@sha256:df4cae8f3a96d175e2e5f992e597550000edbe78fdc2594d5cd8de1a217f504c /uv /bin/uv
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=0 \
    UV_PYTHON=/usr/local/bin/python3.12 \
    UV_PROJECT_ENVIRONMENT=/opt/venv
WORKDIR /src
# Dependencies first (cached unless the lockfile changes), then the project.
COPY pyproject.toml uv.lock ./
RUN uv sync --locked --no-dev --no-install-project
COPY README.md LICENSE ./
COPY src ./src
RUN uv sync --locked --no-dev --no-editable

FROM python:3.12-slim@sha256:aa943ce411423c7582288f18707ff66eddcbaeb510502d747a72aeb34f30d159
RUN groupadd --system --gid 10001 tuisku \
 && useradd --system --uid 10001 --gid 10001 --no-create-home \
      --home-dir /nonexistent --shell /usr/sbin/nologin tuisku
COPY --from=build /opt/venv /opt/venv
WORKDIR /app
COPY alembic.ini ./
COPY migrations ./migrations
# Built-in rule packs (ADR 0006); deployments add their own via TUISKU_RULE_PACK_PATHS.
COPY packs ./packs
ARG TUISKU_BUILD_REVISION=unknown
ENV PATH=/opt/venv/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    TUISKU_ALEMBIC_CONFIG=/app/alembic.ini \
    TUISKU_BUILTIN_PACKS_DIR=/app/packs \
    TUISKU_BUILD_REVISION=$TUISKU_BUILD_REVISION
USER 10001:10001
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/v1/health', timeout=3)"]
# Migrations are NOT run here: deploy `tuisku migrate` as a separate job.
CMD ["tuisku", "api", "--host", "0.0.0.0", "--port", "8080"]
