# Guardrail service image. Build: docker build -t guardrails .
# Nothing secret is baked in: keys, the audit key and the audit log are supplied at run time (see docker-compose.yml).
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Run as an unprivileged user. /data is where the audit log goes (mount a volume there).
RUN useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin guardrails \
 && mkdir /data && chown 10001 /data

WORKDIR /app
COPY pyproject.toml ./
COPY guardrails ./guardrails
RUN pip install ".[api]"

USER 10001

# Production is the default: the service refuses to start without API keys and an audit log.
ENV GUARDRAILS_ENVIRONMENT=production \
    GR_HOST=0.0.0.0 \
    GR_PORT=8000
EXPOSE 8000
VOLUME ["/data"]

# Ready (not just alive): fails when the audit log cannot be written or no keys are loaded.
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD ["python", "-c", "import os,urllib.request;urllib.request.urlopen('http://127.0.0.1:'+os.environ.get('GR_PORT','8000')+'/readyz',timeout=2)"]

CMD ["python", "-m", "guardrails.api"]
