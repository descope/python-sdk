ARG PYTHON_VERSION=3.13
ARG UV_VERSION=0.11.15

FROM ghcr.io/astral-sh/uv:${UV_VERSION} AS uv

FROM python:${PYTHON_VERSION}-slim AS builder
COPY --from=uv /uv /uvx /bin/

ENV UV_LINK_MODE=copy \
    UV_COMPILE_BYTECODE=1 \
    UV_PYTHON_DOWNLOADS=never \
    UV_PROJECT_ENVIRONMENT=/opt/venv

WORKDIR /app
COPY pyproject.toml uv.lock README.md LICENSE ./
COPY descope ./descope
RUN uv sync --frozen --no-dev --extra Flask

FROM python:${PYTHON_VERSION}-slim AS production
ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Run as a non-root user
RUN groupadd --system --gid 1001 app \
    && useradd --system --uid 1001 --gid app --create-home --home-dir /home/app app

COPY --from=builder --chown=app:app /opt/venv /opt/venv
COPY --chown=app:app . /app
WORKDIR /app

USER app

CMD ["python", "samples/otp_web_sample_app.py"]
