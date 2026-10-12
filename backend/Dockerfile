# GhostOps API image (Render, or any Docker host). Build from the repo root:
#   docker build -f backend/Dockerfile -t ghostops-api .
# Runs in hosted mode: GHOSTOPS_HOSTED=1 needs GHOSTOPS_API_KEY and GHOSTOPS_SIGNING_KEY (or GHOSTOPS_HMAC_SECRET)
# at run time (never baked in). Shadow runs go to MiniStack only (MINISTACK_ENDPOINT_URL).
# Infracost is deliberately not installed: it has no API key, only an interactive OAuth
# login, so certificates report cost as null with a note instead of opening a login.

FROM python:3.13-slim AS tools
ARG TERRAFORM_VERSION=1.16.4
ARG TERRAFORM_SHA256=dc94af0eef1147718ad7c8daea792ed199e3e0492eec180d0adafa2a65a879df
ARG OPA_VERSION=1.21.1
ARG OPA_SHA256=668506eb17a2eaa1fce6cc0d1f42ef85125d4ac5bda5fc74d1152d0c77145031
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl unzip \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /dl
RUN curl -fsSLo terraform.zip "https://releases.hashicorp.com/terraform/${TERRAFORM_VERSION}/terraform_${TERRAFORM_VERSION}_linux_amd64.zip" \
    && echo "${TERRAFORM_SHA256}  terraform.zip" | sha256sum -c - \
    && unzip -q terraform.zip terraform \
    && curl -fsSLo opa "https://github.com/open-policy-agent/opa/releases/download/v${OPA_VERSION}/opa_linux_amd64_static" \
    && echo "${OPA_SHA256}  opa" | sha256sum -c - \
    && chmod 0755 terraform opa

# Pre-fill the provider cache so a cold container does not download the ~700 MB AWS
# provider on its first analysis. Set PREFETCH_PROVIDERS=0 for a smaller image.
ARG PREFETCH_PROVIDERS=1
ENV TF_PLUGIN_CACHE_DIR=/dl/plugin-cache
RUN mkdir -p "$TF_PLUGIN_CACHE_DIR" prefetch && if [ "$PREFETCH_PROVIDERS" = "1" ]; then \
      printf '%s\n' 'terraform {' '  required_providers {' \
        '    aws = { source = "hashicorp/aws", version = "~> 5.0" }' \
        '    archive = { source = "hashicorp/archive", version = "~> 2.4" }' '  }' '}' > prefetch/main.tf \
      && ./terraform -chdir=prefetch init -backend=false -input=false -no-color >/dev/null; \
    fi


FROM python:3.13-slim
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    GHOSTOPS_HOSTED=1 \
    GHOSTOPS_HOST=0.0.0.0 \
    PORT=8000 \
    GHOSTOPS_DB_PATH=/app/data/ghostops.db \
    CHECKPOINT_DISABLE=1 \
    BROWSER=none

COPY --from=tools /dl/terraform /dl/opa /usr/local/bin/
RUN useradd --create-home --uid 10001 ghostops

# The app finds rules/, demo/ and the plugin cache relative to the source tree, so it
# runs from /app/backend (editable install) rather than from site-packages.
WORKDIR /app
COPY backend/pyproject.toml backend/requirements.txt backend/
COPY backend/app backend/app
RUN pip install -e ./backend
COPY backend/rules backend/rules
COPY backend/tests/fixtures/bad_plan.json backend/tests/fixtures/good_plan.json backend/tests/fixtures/
COPY demo/bad/main.tf demo/bad/
COPY demo/good/main.tf demo/good/
COPY --from=tools --chown=ghostops:ghostops /dl/plugin-cache /app/.terraform-plugin-cache
RUN mkdir -p /app/data && chown ghostops:ghostops /app/data /app/.terraform-plugin-cache

USER ghostops
WORKDIR /app/backend
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import os, urllib.request; urllib.request.urlopen('http://127.0.0.1:%s/health' % os.environ.get('PORT', '8000'), timeout=4)"
CMD ["python", "-m", "app.server"]
