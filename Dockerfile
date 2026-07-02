# syntax=docker/dockerfile:1
# ==============================================================================
#  PySentinel v2.1 — Production Dockerfile
#
#  Build:  DOCKER_BUILDKIT=1 docker build -t pysentinel:2.1 .
#  Run  :  docker run --rm -v $(pwd)/reports:/home/scanner/pysentinel_reports \
#             pysentinel:2.1 nsepython --html
# ==============================================================================

FROM python:3.11-slim AS toolchain

# BuildKit pip cache: survives failed builds — semgrep (34MB) won't restart on timeout
RUN --mount=type=cache,target=/root/.cache/pip \
    pip install --timeout 300 --retries 10 \
        "bandit==1.8.3" \
        "pip-audit==2.8.0" \
        "safety==3.3.1" \
        "detect-secrets==1.5.0"

RUN --mount=type=cache,target=/root/.cache/pip \
    pip install --timeout 600 --retries 10 \
        "semgrep==1.112.0"

# ── Final runtime image ────────────────────────────────────────────────────────
FROM python:3.11-slim AS final

LABEL org.opencontainers.image.title="PySentinel"
LABEL org.opencontainers.image.description="Python module security scanner"
LABEL org.opencontainers.image.version="2.1"

RUN apt-get update && apt-get install -y --no-install-recommends \
        git curl file ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# ── ripgrep ───────────────────────────────────────────────────────────────────
ARG RG_VERSION="14.1.1"
RUN set -eux; \
    ARCH=$(dpkg --print-architecture); \
    case "$ARCH" in \
        amd64) RG_ARCH="x86_64-unknown-linux-musl" ;; \
        arm64) RG_ARCH="aarch64-unknown-linux-gnu"  ;; \
        *)     echo "Unsupported arch: $ARCH" >&2 && exit 1 ;; \
    esac; \
    curl -sSfL --retry 5 \
        "https://github.com/BurntSushi/ripgrep/releases/download/${RG_VERSION}/ripgrep-${RG_VERSION}-${RG_ARCH}.tar.gz" \
    | tar -xz --strip-components=1 -C /usr/local/bin "ripgrep-${RG_VERSION}-${RG_ARCH}/rg"; \
    rg --version

# ── gitleaks ──────────────────────────────────────────────────────────────────
ARG GITLEAKS_VERSION="8.21.2"
RUN set -eux; \
    ARCH=$(dpkg --print-architecture); \
    case "$ARCH" in \
        amd64) GL_ARCH="x64"   ;; \
        arm64) GL_ARCH="arm64" ;; \
        *)     echo "Unsupported arch: $ARCH" >&2 && exit 1 ;; \
    esac; \
    curl -sSfL --retry 5 \
        "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_${GL_ARCH}.tar.gz" \
    | tar -xz -C /usr/local/bin gitleaks; \
    gitleaks version

# ── Copy Python tools from toolchain stage ────────────────────────────────────
COPY --from=toolchain /usr/local/lib/python3.11/site-packages \
                      /usr/local/lib/python3.11/site-packages
COPY --from=toolchain /usr/local/bin/bandit         /usr/local/bin/bandit
COPY --from=toolchain /usr/local/bin/semgrep        /usr/local/bin/semgrep
COPY --from=toolchain /usr/local/bin/pysemgrep      /usr/local/bin/pysemgrep
COPY --from=toolchain /usr/local/bin/pip-audit      /usr/local/bin/pip-audit
COPY --from=toolchain /usr/local/bin/safety         /usr/local/bin/safety
COPY --from=toolchain /usr/local/bin/detect-secrets /usr/local/bin/detect-secrets

# ── App files ─────────────────────────────────────────────────────────────────
COPY scanner/pysentinel.sh        /usr/local/bin/pysentinel.sh
COPY reporter/generate_report.py  /opt/pysentinel/reporter/generate_report.py
COPY reporter/assets/report.css   /opt/pysentinel/reporter/assets/report.css
COPY reporter/assets/report.js    /opt/pysentinel/reporter/assets/report.js
RUN chmod 755 /usr/local/bin/pysentinel.sh && \
    chmod -R a+rX /opt/pysentinel/reporter

# ── Non-root user ─────────────────────────────────────────────────────────────
RUN useradd -m -u 1001 -s /bin/bash scanner
USER scanner
WORKDIR /home/scanner
ENV HOME=/home/scanner

# Tell pysentinel.sh it is running inside Docker — skip venv + pip install
ENV PYSENTINEL_DOCKER=1
# Tell pysentinel.sh where the reporter lives
ENV PYSENTINEL_REPORTER=/opt/pysentinel/reporter

# Verify tools as non-root
RUN python3  --version && \
    bandit    --version && \
    semgrep   --version && \
    pip-audit --version && \
    gitleaks  version   && \
    rg        --version

RUN mkdir -p /home/scanner/pysentinel_reports
VOLUME ["/home/scanner/pysentinel_reports"]

HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
    CMD python3 -c "import sys; sys.exit(0)"

ENTRYPOINT ["/usr/local/bin/pysentinel.sh"]