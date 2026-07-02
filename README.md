# PySentinel v2.1

**360° Python module security scanner** — Feed it a PyPI name or GitHub URL, get a full security report with a SAFE / CAUTION / AVOID verdict.

---

## Folder structure

```
pysentinel/
├── Dockerfile                  ← Image definition
├── docker-compose.yml          ← Developer convenience
├── scan.sh                     ← Single-command launcher (host)
├── .dockerignore
├── README.md
├── scanner/
│   └── pysentinel.sh           ← Core scan engine (14 steps)
└── reporter/
    ├── generate_report.py      ← HTML report generator
    └── assets/
        ├── report.css          ← Dark dashboard theme
        └── report.js           ← Filter, search, collapsible UI
```

---

## What it scans

| Step | Check | Tool |
|---|---|---|
| 3 | PyPI metadata & typosquatting signals | PyPI JSON API |
| 4 | Install-hook analysis (setup.py, pyproject.toml) | rg / grep |
| 5 | Obfuscation & malware patterns | rg / grep |
| 6 | Network exfiltration patterns | rg / grep |
| 7 | Filesystem & credential snooping | rg / grep |
| 7 | Hardcoded secrets — current files | detect-secrets |
| 8 | **Hardcoded secrets — full git history** | **gitleaks** |
| 9 | SAST | bandit |
| 10 | SAST (auto + p/python + p/security-audit + p/secrets) | semgrep |
| 11 | CVE scan — full dependency tree | pip-audit |
| 12 | CVE scan — Safety DB | safety |
| 13 | `__init__.py` side-effect AST analysis | Python ast |
| 14 | Binary & shell script audit | file |

---

## Developer Usage

> For engineers running scans on their **local machine** from source.

### Prerequisites

```bash
# macOS
brew install docker

# Verify
docker --version
docker compose version
```

### 1 — Clone / get the files

```
pysentinel/
├── Dockerfile
├── docker-compose.yml
├── scanner/pysentinel.sh
└── reporter/
    ├── generate_report.py
    └── assets/{report.css, report.js}
```

### 2 — Build the image

```bash
# BuildKit must be on (handles the semgrep 34MB download gracefully)
DOCKER_BUILDKIT=1 docker compose build
```

First build takes ~5 minutes (downloads semgrep, gitleaks, ripgrep).
Subsequent builds are instant — layers are cached.

### 3 — Run a scan

```bash
# Scan a PyPI package
docker compose run --rm pysentinel nsepython

# Scan a GitHub repository
docker compose run --rm pysentinel https://github.com/aeron7/nsepython

# With HTML report (opens from ./reports/*.html)
docker compose run --rm pysentinel nsepython --html
docker compose run --rm pysentinel https://github.com/aeron7/nsepython --html
```

Reports land in `./reports/` — a text report always, HTML when `--html` is passed.

### 4 — Open the HTML report

```bash
# macOS
open reports/pysentinel_*.html

# Linux
xdg-open reports/pysentinel_*.html
```

---

## Production Usage

> For DevOps / Platform engineers building and distributing the image.

### Step 1 — Build the image

```bash
# Enable BuildKit (required for pip cache layer — avoids semgrep timeout)
export DOCKER_BUILDKIT=1

# Build and tag with ECR URI
docker build \
  -t <ACCOUNT_ID>.dkr.ecr.<REGION>.amazonaws.com/pysentinel:2.1 \
  -t <ACCOUNT_ID>.dkr.ecr.<REGION>.amazonaws.com/pysentinel:latest \
  .
```

### Step 2 — Authenticate to ECR

```bash
aws ecr get-login-password --region <REGION> \
  | docker login --username AWS --password-stdin \
    <ACCOUNT_ID>.dkr.ecr.<REGION>.amazonaws.com
```

### Step 3 — Push to ECR

```bash
docker push <ACCOUNT_ID>.dkr.ecr.<REGION>.amazonaws.com/pysentinel:2.1
docker push <ACCOUNT_ID>.dkr.ecr.<REGION>.amazonaws.com/pysentinel:latest
```

### Step 4 — Colleagues pull and scan

Colleagues need **only Docker**. No source files, no build step.

```bash
# Pull the image
docker pull <ACCOUNT_ID>.dkr.ecr.<REGION>.amazonaws.com/pysentinel:2.1

# Create a reports folder
mkdir -p ~/pysentinel-reports

# Run a scan — text report
docker run --rm \
  -v ~/pysentinel-reports:/home/scanner/pysentinel_reports \
  <ACCOUNT_ID>.dkr.ecr.<REGION>.amazonaws.com/pysentinel:2.1 \
  nsepython

# Run a scan — text + HTML report
docker run --rm \
  -v ~/pysentinel-reports:/home/scanner/pysentinel_reports \
  <ACCOUNT_ID>.dkr.ecr.<REGION>.amazonaws.com/pysentinel:2.1 \
  nsepython --html

# Scan a GitHub URL
docker run --rm \
  -v ~/pysentinel-reports:/home/scanner/pysentinel_reports \
  <ACCOUNT_ID>.dkr.ecr.<REGION>.amazonaws.com/pysentinel:2.1 \
  https://github.com/aeron7/nsepython --html
```

### Optional — set an alias (saves retyping the image URI)

Add to `~/.bashrc` or `~/.zshrc`:

```bash
export PYSENTINEL_IMAGE="<ACCOUNT_ID>.dkr.ecr.<REGION>.amazonaws.com/pysentinel:2.1"
alias pysentinel='docker run --rm -v ~/pysentinel-reports:/home/scanner/pysentinel_reports $PYSENTINEL_IMAGE'
```

Reload shell:

```bash
source ~/.bashrc    # or: source ~/.zshrc
```

Then:

```bash
pysentinel nsepython --html
pysentinel requests --html
pysentinel https://github.com/org/repo --html
```

### Step 5 — Re-scan policy

```bash
# Run after every dependency version upgrade
pysentinel <package>==<new-version> --html
```

Most supply-chain attacks land in patch releases, not major versions.

---

## Verdict logic

| Score | Verdict |
|---|---|
| Any Critical | 🚨 AVOID — Critical security risks |
| ≥ 3 High | ❌ AVOID — Multiple high severity issues |
| 1–2 High or ≥ 5 Medium | ⚠️ Use with caution |
| Low / Medium only | ℹ️ Low risk — standard due diligence |
| Clean | ✅ Likely safe |
