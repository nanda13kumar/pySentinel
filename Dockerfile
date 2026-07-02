# ==============================================================================
#  PySentinel v2.1 — Docker Image
#  
#  What's pre-installed so colleagues need ZERO setup:
#    • Python 3.11 + bandit, semgrep, pip-audit, safety, detect-secrets
#    • gitleaks  (Go binary — git history secret scanning)
#    • ripgrep   (rg — fast pattern scanner)
#    • git, curl, file (system utils)
#
#  Build:  docker build -t pysentinel .
#  Run  :  docker run --rm -v $(pwd)/reports:/home/scanner/pysentinel_reports pysentinel nsepython
#  HTML :  docker run --rm -v $(pwd)/reports:/home/scanner/pysentinel_reports pysentinel nsepython --html
# ==============================================================================

FROM python:3.11-slim

LABEL maintainer="InfoSec Team"
LABEL description="PySentinel — Python module security scanner"
LABEL version="2.1"

# ── System packages ────────────────────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    file \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# ── ripgrep (rg) — fast pattern scanner ───────────────────────────────────────
ARG RG_VERSION="14.1.1"
RUN ARCH=$(dpkg --print-architecture) && \
    case "$ARCH" in \
        amd64)  RG_ARCH="x86_64-unknown-linux-musl" ;; \
        arm64)  RG_ARCH="aarch64-unknown-linux-gnu" ;; \
        *)      echo "Unsupported arch: $ARCH" && exit 1 ;; \
    esac && \
    curl -sSfL \
        "https://github.com/BurntSushi/ripgrep/releases/download/${RG_VERSION}/ripgrep-${RG_VERSION}-${RG_ARCH}.tar.gz" \
        | tar -xz --strip-components=1 -C /usr/local/bin \
            "ripgrep-${RG_VERSION}-${RG_ARCH}/rg" && \
    rg --version

# ── gitleaks — git history secret scanner ─────────────────────────────────────
ARG GITLEAKS_VERSION="8.21.2"
RUN ARCH=$(dpkg --print-architecture) && \
    case "$ARCH" in \
        amd64)  GL_ARCH="x64" ;; \
        arm64)  GL_ARCH="arm64" ;; \
        *)      echo "Unsupported arch: $ARCH" && exit 1 ;; \
    esac && \
    curl -sSfL \
        "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_${GL_ARCH}.tar.gz" \
        | tar -xz -C /usr/local/bin gitleaks && \
    gitleaks version

# ── Python security tools ──────────────────────────────────────────────────────
# Step 1: lightweight tools first — fast, low risk of timeout
RUN pip install --no-cache-dir --timeout 120 --retries 5 \
    "bandit==1.8.3" \
    "pip-audit==2.8.0" \
    "safety==3.3.1" \
    "detect-secrets==1.5.0"

# Step 2: semgrep separately — 34MB wheel, needs its own timeout budget
# If this still times out on your network, set: --build-arg SEMGREP_TIMEOUT=600
ARG SEMGREP_TIMEOUT=300
RUN pip install --no-cache-dir --timeout ${SEMGREP_TIMEOUT} --retries 5 \
    "semgrep==1.112.0"

# ── Scanner script ─────────────────────────────────────────────────────────────
COPY pysentinel.sh /usr/local/bin/pysentinel.sh
RUN chmod 755 /usr/local/bin/pysentinel.sh

# ── Non-root user for defence-in-depth ────────────────────────────────────────
# Running as non-root limits blast radius if the scanned package has exploits
RUN useradd -m -u 1001 scanner
USER scanner
WORKDIR /home/scanner

# Reports directory — mount here from host
RUN mkdir -p /home/scanner/pysentinel_reports
VOLUME ["/home/scanner/pysentinel_reports"]

# Tell pysentinel.sh it is running inside Docker — skips venv + pip install
ENV PYSENTINEL_DOCKER=1
ENV HOME=/home/scanner

ENTRYPOINT ["/usr/local/bin/pysentinel.sh"]
CMD ["--help"]