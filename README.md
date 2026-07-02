# PySentinel v2.1 — Python Module Security Scanner

A 360° security scanner for Python packages before you add them to your project.
Feed it a PyPI name or a GitHub URL — it scans, reports, and cleans up.

---

## What it scans

| # | Check | Tools |
|---|---|---|
| 1 | PyPI metadata & typosquatting signals | PyPI JSON API |
| 2 | Install-hook analysis (setup.py, pyproject.toml) | rg / grep |
| 3 | Obfuscation & malware patterns (eval, exec, marshal, pickle…) | rg / grep |
| 4 | Network exfiltration patterns (socket, requests.post, smtplib…) | rg / grep |
| 5 | Filesystem credential snooping (/.ssh, /.aws, /etc/shadow…) | rg / grep |
| 6 | Hardcoded secrets in current file tree | detect-secrets |
| 7 | **Hardcoded secrets in full git history** | **gitleaks** |
| 8 | SAST | bandit |
| 9 | SAST (auto + p/python + p/security-audit + p/secrets) | semgrep |
| 10 | CVE scan — full dependency tree | pip-audit |
| 11 | CVE scan — Safety DB | safety |
| 12 | `__init__.py` side-effect AST analysis | Python ast |
| 13 | Non-Python file audit (binaries, .so, shell scripts) | file |
| 14 | Verdict: SAFE / CAUTION / AVOID with scoring | — |

All temp files removed on exit — guaranteed via `trap`.

---

## ✅ Already have the image? Jump straight to running scans

> **For colleagues who pulled the image from ECR (or any registry) —
> no Dockerfile, no build, no setup required. Docker is all you need.**

### Create a folder for your reports first (one-time)

```bash
mkdir -p ~/pysentinel-reports
```

### Scan a PyPI package

```bash
docker run --rm \
  -v ~/pysentinel-reports:/home/scanner/pysentinel_reports \
  <YOUR-ECR-ACCOUNT>.dkr.ecr.<REGION>.amazonaws.com/pysentinel:2.1 \
  nsepython
```

### Scan a GitHub repository

```bash
docker run --rm \
  -v ~/pysentinel-reports:/home/scanner/pysentinel_reports \
  <YOUR-ECR-ACCOUNT>.dkr.ecr.<REGION>.amazonaws.com/pysentinel:2.1 \
  https://github.com/aeron7/nsepython
```

### Get a text + HTML report

```bash
docker run --rm \
  -v ~/pysentinel-reports:/home/scanner/pysentinel_reports \
  <YOUR-ECR-ACCOUNT>.dkr.ecr.<REGION>.amazonaws.com/pysentinel:2.1 \
  nsepython --html
```

Reports are saved to `~/pysentinel-reports/` on your machine.
Open the `.html` file in any browser for a formatted view.

### Tip — set a short alias so you don't retype the image name

Add this to your `~/.bashrc` or `~/.zshrc`:

```bash
export PYSENTINEL_IMAGE="<YOUR-ECR-ACCOUNT>.dkr.ecr.<REGION>.amazonaws.com/pysentinel:2.1"
alias pysentinel='docker run --rm -v ~/pysentinel-reports:/home/scanner/pysentinel_reports $PYSENTINEL_IMAGE'
```

Then reload your shell:

```bash
source ~/.bashrc    # or: source ~/.zshrc
```

Now scan anything with a single word:

```bash
pysentinel nsepython
pysentinel https://github.com/aeron7/nsepython
pysentinel requests --html
pysentinel boto3 --html
```

---

## Option A — Shell Script (quick, individual use without Docker)

### Prerequisites

```bash
# Required
brew install python3 git curl          # macOS
apt install python3 git curl           # Ubuntu/Debian

# Strongly recommended (adds git history scanning)
brew install gitleaks                  # macOS
# Linux:
curl -sSfL https://github.com/gitleaks/gitleaks/releases/latest/download/gitleaks_$(uname -s)_x64.tar.gz \
  | tar -xz -C /usr/local/bin

# Optional (faster pattern scanning)
brew install ripgrep                   # macOS
apt install ripgrep                    # Ubuntu/Debian
```

### Run

```bash
chmod +x pysentinel.sh

./pysentinel.sh nsepython
./pysentinel.sh https://github.com/aeron7/nsepython
./pysentinel.sh nsepython --html
```

Reports saved to `~/pysentinel_reports/`.

---

## Option B — Docker (build from source)

If you want to build the image yourself rather than pulling from ECR:

```bash
# 1. Put Dockerfile, pysentinel.sh, scan.sh, .dockerignore in one folder
# 2. Make scan.sh executable
chmod +x scan.sh

# 3. Run — scan.sh builds the image automatically on first run
./scan.sh nsepython
./scan.sh https://github.com/aeron7/nsepython --html
```

`scan.sh` detects whether the image exists and builds it if not.
Subsequent runs are instant — no rebuild.

### Why Docker for teams?

| | Shell script | Docker |
|---|---|---|
| Colleague setup | Install 6+ tools manually | `docker pull` — done |
| Tool versions | Vary per machine | Pinned, identical for everyone |
| gitleaks included | Must install separately | ✅ Pre-installed |
| ripgrep included | Must install separately | ✅ Pre-installed |
| Reproducible scans | Depends on host | ✅ Same result everywhere |
| Extra isolation | Relies on venv | ✅ Full container sandbox |

---

## Verdict logic

| Score | Verdict |
|---|---|
| Any Critical issue | 🚨 AVOID — Critical security risks |
| ≥ 3 High issues | ❌ AVOID — Multiple high severity issues |
| 1–2 High or ≥ 5 Medium | ⚠️ Use with caution — review before deploying |
| Low / Medium only | ℹ️ Low risk — standard due diligence advised |
| Clean | ✅ Likely safe |

---

## Answered: your original 4 questions

1. **Is the code clean / malicious?** → Steps 2–5 (install hooks, obfuscation, network, FS snooping)
2. **SAST tool?** → Bandit (Step 8) + Semgrep with `--config=auto` (Step 9)
3. **CVE identification?** → pip-audit (Step 10) + Safety (Step 11)
4. **Is it safe for your server?** → gitleaks (Step 7) + network pattern scan (Step 4) + FS snooping (Step 5)

---

## Re-scan policy

Run PySentinel **after every version upgrade** of a dependency.
Most supply-chain attacks happen in patch releases, not major versions.