#!/usr/bin/env bash
# ==============================================================================
#  PySentinel v2.1 — Python Module Security Scanner
#  Author : InfoSec Automation (Claude)
#  Usage  : ./pysentinel.sh <pypi-package-name | github-url> [--html]
#  Example: ./pysentinel.sh nsepython
#           ./pysentinel.sh https://github.com/aeron7/nsepython
#           ./pysentinel.sh requests --html
#
#  What it does:
#    1.  Acquires source code (PyPI or GitHub) into an isolated temp directory
#    2.  PyPI metadata & typosquatting analysis
#    3.  Install-hook analysis (setup.py / pyproject.toml)
#    4.  Obfuscation & malware pattern detection
#    5.  Network exfiltration pattern scan  (uses rg if available, else grep)
#    6.  Filesystem credential snooping scan
#    7.  Hardcoded secrets — detect-secrets  (current file tree)
#    8.  Hardcoded secrets — gitleaks        (full git commit history) ← NEW
#    9.  SAST — Bandit
#    10. SAST — Semgrep  (--config=auto + p/python + p/security-audit + p/secrets)
#    11. CVE scan — pip-audit
#    12. CVE scan — Safety
#    13. __init__.py side-effect AST analysis
#    14. Non-Python file audit (binaries, shell scripts)
#    15. Verdict + scored report
#    16. Removes ALL temp files on exit (trap-guaranteed)
#
#  v2.1 changes (vs v2.0):
#    + gitleaks step for full git-history secret scanning
#    + ripgrep (rg) support with grep fallback — faster pattern scans
#    + semgrep now also runs --config=auto for broader language coverage
#    + git clone uses full depth when gitleaks is available
#    + pre-flight detects optional tools (gitleaks, rg) and reports status
# ==============================================================================

set -euo pipefail
IFS=$'\n\t'

# ── Arguments ──────────────────────────────────────────────────────────────────
INPUT="${1:-}"
GENERATE_HTML=false
[[ "${2:-}" == "--html" ]] && GENERATE_HTML=true

# ── Paths ──────────────────────────────────────────────────────────────────────
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
REPORT_DIR="$HOME/pysentinel_reports"
REPORT_TXT="$REPORT_DIR/pysentinel_${TIMESTAMP}.txt"
REPORT_HTML="$REPORT_DIR/pysentinel_${TIMESTAMP}.html"
SCAN_ROOT=$(mktemp -d /tmp/pysentinel_XXXXXX)
SOURCE_DIR="$SCAN_ROOT/source"
VENV_DIR="$SCAN_ROOT/.venv"
DOWNLOAD_DIR="$SCAN_ROOT/download"
TOOLS_LOG="$SCAN_ROOT/tools.log"

# ── Structured-report data files (consumed by reporter/generate_report.py) ────
CUSTOM_FINDINGS_JSONL="$SCAN_ROOT/custom_findings.jsonl"
PYPI_META_JSON="$SCAN_ROOT/pypi_meta.json"
VERDICT_JSON="$SCAN_ROOT/verdict.json"
GITLEAKS_JSON="$SCAN_ROOT/gitleaks.json"
export CUSTOM_FINDINGS_JSONL
: > "$CUSTOM_FINDINGS_JSONL"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT_REPORTER_DIR="$(cd "$SCRIPT_DIR/../reporter" 2>/dev/null && pwd || true)"

START_EPOCH=$(date +%s)
STARTED_AT_ISO=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# ── Counters (issue severity buckets) ─────────────────────────────────────────
CRITICAL=0
HIGH=0
MEDIUM=0
LOW=0

# ── ANSI colours ──────────────────────────────────────────────────────────────
RED='\033[0;31m'; LRED='\033[1;31m'
YEL='\033[1;33m'; GRN='\033[0;32m'
CYN='\033[0;36m'; BLU='\033[0;34m'
BOLD='\033[1m';   NC='\033[0m'

# ==============================================================================
#  CLEANUP — guaranteed to run on exit (even ctrl-c)
# ==============================================================================
cleanup() {
    echo "" >&2
    echo -e "${CYN}[cleanup]${NC} Removing all temporary scan data from ${SCAN_ROOT} …" >&2
    rm -rf "$SCAN_ROOT"
    echo -e "${GRN}[cleanup]${NC} Done — no traces left on disk." >&2
}
trap cleanup EXIT

# ==============================================================================
#  HELPERS
# ==============================================================================
usage() {
    echo "Usage: $0 <pypi-name | github-url> [--html]"
    echo "  $0 nsepython"
    echo "  $0 https://github.com/aeron7/nsepython --html"
    exit 1
}
[[ -z "$INPUT" ]] && usage

tee_report()  { tee -a "$REPORT_TXT"; }

log()      { echo -e "${BLU}[info]${NC}    $*"                    | tee_report; }
ok()       { echo -e "${GRN}[pass]${NC}    $*"                    | tee_report; }
warn()     { echo -e "${YEL}[medium]${NC}  $*"                    | tee_report; MEDIUM=$((MEDIUM+1)); }
high_f()   { echo -e "${RED}[high]${NC}    $*"                    | tee_report; HIGH=$((HIGH+1)); }
crit_f()   { echo -e "${LRED}[CRITICAL]${NC} $*"                  | tee_report; CRITICAL=$((CRITICAL+1)); }
low_f()    { echo -e "${CYN}[low]${NC}     $*"                    | tee_report; LOW=$((LOW+1)); }
section()  { echo -e "\n${BOLD}${CYN}━━━━━━  $*  ━━━━━━${NC}\n" | tee_report; }
divider()  { echo -e "${BOLD}──────────────────────────────────────────────${NC}" | tee_report; }

cmd_exists() { command -v "$1" &>/dev/null; }

python3_run() {
    # Run python inside the venv
    "$VENV_DIR/bin/python3" "$@"
}

pip_run() {
    "$VENV_DIR/bin/pip" "$@"
}

# rg_scan: use ripgrep if available (10-100x faster), else grep
# Usage: rg_scan <pattern> <directory> [extra rg/grep flags]
rg_scan() {
    local pattern="$1"; local dir="$2"
    if cmd_exists rg; then
        rg --no-heading -n "$pattern" "$dir" --glob "*.py" 2>/dev/null | head -5 || true
    else
        grep -rn "$pattern" "$dir" --include="*.py" 2>/dev/null | head -5 || true
    fi
}

# rg_exists: returns 0 if pattern found, 1 if not
rg_exists() {
    local pattern="$1"; local dir="$2"
    if cmd_exists rg; then
        rg -ql "$pattern" "$dir" --glob "*.py" 2>/dev/null | grep -q .
    else
        grep -rql "$pattern" "$dir" --include="*.py" 2>/dev/null
    fi
}

# record_finding: append one structured finding to CUSTOM_FINDINGS_JSONL.
# Values are passed via env vars (never string-interpolated into the python
# source) so file paths / matched code can contain any characters safely.
# Usage: record_finding <category> <severity> <pattern> <description> <file> <line> <line_content>
record_finding() {
    local category="$1" severity="$2" pattern="$3" description="$4"
    local file="$5" line="$6" content="$7"
    CATEGORY="$category" SEVERITY="$severity" PATTERN="$pattern" DESCRIPTION="$description" \
    FFILE="$file" FLINE="$line" FCONTENT="$content" \
    python3_run -c "
import json, os
rec = {
    'category': os.environ.get('CATEGORY', ''),
    'severity': os.environ.get('SEVERITY', ''),
    'pattern': os.environ.get('PATTERN', ''),
    'description': os.environ.get('DESCRIPTION', ''),
    'file': os.environ.get('FFILE', ''),
    'line_number': int(os.environ['FLINE']) if os.environ.get('FLINE', '').strip().isdigit() else None,
    'line_content': os.environ.get('FCONTENT', ''),
}
with open(os.environ['CUSTOM_FINDINGS_JSONL'], 'a') as fh:
    fh.write(json.dumps(rec) + chr(10))
" 2>>"$TOOLS_LOG" || true
}

# record_hits: parse ripgrep/grep "file:line:content" output lines and
# record one finding per hit.
# Usage: record_hits <category> <severity> <pattern> <description> <hits-text>
record_hits() {
    local category="$1" severity="$2" pattern="$3" description="$4" hits="$5"
    [[ -z "$hits" ]] && return 0
    local hit f rest ln content
    while IFS= read -r hit; do
        [[ -z "$hit" ]] && continue
        f="${hit%%:*}"
        rest="${hit#*:}"
        ln="${rest%%:*}"
        content="${rest#*:}"
        f="${f#"$SOURCE_DIR"/}"
        record_finding "$category" "$severity" "$pattern" "$description" "$f" "$ln" "$content"
    done <<< "$hits"
}

# ==============================================================================
#  BANNER
# ==============================================================================
mkdir -p "$REPORT_DIR" "$SOURCE_DIR" "$DOWNLOAD_DIR"

{
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  PySentinel v2.1 — Python Module Security Scanner"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Target    : $INPUT"
echo "  Scan ID   : $TIMESTAMP"
echo "  Started   : $(date)"
echo "  Report    : $REPORT_TXT"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
} | tee "$REPORT_TXT"

# ==============================================================================
#  STEP 0: Pre-flight checks
# ==============================================================================
section "STEP 0: Pre-flight Checks"

MISSING_PREREQS=()
for dep in python3 git curl; do
    cmd_exists "$dep" || MISSING_PREREQS+=("$dep")
done

if [[ ${#MISSING_PREREQS[@]} -gt 0 ]]; then
    crit_f "Missing required system tools: ${MISSING_PREREQS[*]}"
    echo "Install them with your system package manager and re-run."
    exit 2
fi
ok "System prerequisites: python3, git, curl — all present"

# Optional tools — enrich the scan when present
HAS_GITLEAKS=false
HAS_RG=false
cmd_exists gitleaks && HAS_GITLEAKS=true
cmd_exists rg       && HAS_RG=true

if $HAS_GITLEAKS; then
    ok "gitleaks detected — git history secret scan ENABLED"
else
    warn "gitleaks not found — git history secret scan SKIPPED"
    echo "    Install: https://github.com/gitleaks/gitleaks#installing" | tee -a "$REPORT_TXT"
    echo "    macOS  : brew install gitleaks" | tee -a "$REPORT_TXT"
    echo "    Linux  : curl -sSfL https://github.com/gitleaks/gitleaks/releases/latest/download/gitleaks_\$(uname -s)_x64.tar.gz | tar -xz -C /usr/local/bin" | tee -a "$REPORT_TXT"
fi

if $HAS_RG; then
    ok "ripgrep (rg) detected — using fast pattern scanner"
else
    log "ripgrep not found — falling back to grep (functionally identical, slower)"
fi

# ==============================================================================
#  STEP 1: Tool environment setup
#  Docker mode  → tools pre-installed in image, use system paths, skip venv
#  Host mode    → create isolated venv and pip-install everything
# ==============================================================================
section "STEP 1: Setting Up Scan Environment"

if [[ "${PYSENTINEL_DOCKER:-}" == "1" ]]; then
    # ── Docker mode ───────────────────────────────────────────────────────────
    # All tools were baked into the image at build time.
    # Using system paths directly — no venv, no pip install, no network calls.
    ok "Docker mode — using pre-installed tools (skipping venv and pip install)"
    BANDIT="bandit"
    SEMGREP="semgrep"
    PIP_AUDIT="pip-audit"
    SAFETY="safety"
    DET_SECRETS="detect-secrets"
    python3_run() { python3 "$@"; }
    pip_run()     { pip "$@";     }
else
    # ── Host mode ─────────────────────────────────────────────────────────────
    # Running directly on the host — isolate everything in a temp venv so
    # nothing touches the system Python.
    log "Host mode — creating isolated virtualenv in $VENV_DIR …"
    python3 -m venv "$VENV_DIR" >> "$TOOLS_LOG" 2>&1

    log "Installing security tools (bandit, semgrep, pip-audit, safety, detect-secrets) …"
    "$VENV_DIR/bin/pip" install --quiet --upgrade \
        pip \
        bandit \
        semgrep \
        pip-audit \
        safety \
        detect-secrets \
        requests \
        >> "$TOOLS_LOG" 2>&1

    ok "Tools installed inside venv — system Python untouched"
    BANDIT="$VENV_DIR/bin/bandit"
    SEMGREP="$VENV_DIR/bin/semgrep"
    PIP_AUDIT="$VENV_DIR/bin/pip-audit"
    SAFETY="$VENV_DIR/bin/safety"
    DET_SECRETS="$VENV_DIR/bin/detect-secrets"
fi

# ==============================================================================
#  STEP 2: Detect input type & acquire source code
# ==============================================================================
section "STEP 2: Acquiring Source Code"

PACKAGE_NAME=""
IS_GITHUB=false

if [[ "$INPUT" == *"github.com"* ]]; then
    IS_GITHUB=true
    GITHUB_URL="${INPUT%.git}"   # strip trailing .git if present
    PACKAGE_NAME=$(basename "$GITHUB_URL")
    TARGET_URL="$GITHUB_URL"
    log "Detected GitHub URL → $GITHUB_URL"
    if $HAS_GITLEAKS; then
        log "Cloning FULL history (required for gitleaks git-history scan) …"
        git clone "$GITHUB_URL" "$SOURCE_DIR" >> "$TOOLS_LOG" 2>&1 \
            || { crit_f "git clone failed — check URL / network"; exit 3; }
        ok "Full repository cloned to isolated temp dir (git history preserved for gitleaks)"
    else
        log "Cloning shallow (depth=1) — install gitleaks to enable history scan …"
        git clone --depth=1 "$GITHUB_URL" "$SOURCE_DIR" >> "$TOOLS_LOG" 2>&1 \
            || { crit_f "git clone failed — check URL / network"; exit 3; }
        ok "Repository cloned (shallow) to isolated temp dir"
    fi
else
    PACKAGE_NAME="$INPUT"
    TARGET_URL="https://pypi.org/project/${PACKAGE_NAME}/"
    log "Detected PyPI package → $PACKAGE_NAME"

    # Verify package exists on PyPI
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
        "https://pypi.org/pypi/${PACKAGE_NAME}/json")
    [[ "$HTTP_CODE" == "200" ]] \
        || { crit_f "Package '$PACKAGE_NAME' not found on PyPI (HTTP $HTTP_CODE)"; exit 4; }

    log "Downloading source distribution …"
    "$VENV_DIR/bin/pip" download \
        --no-deps --no-binary :all: \
        -d "$DOWNLOAD_DIR" \
        "$PACKAGE_NAME" \
        >> "$TOOLS_LOG" 2>&1 \
        || {
            warn "Source dist unavailable — falling back to wheel"
            "$VENV_DIR/bin/pip" download \
                --no-deps \
                -d "$DOWNLOAD_DIR" \
                "$PACKAGE_NAME" \
                >> "$TOOLS_LOG" 2>&1
        }

    log "Extracting archive …"
    for f in "$DOWNLOAD_DIR"/*; do
        case "$f" in
            *.tar.gz) tar xzf "$f" -C "$SOURCE_DIR" --strip-components=1 2>>"$TOOLS_LOG" ;;
            *.zip)    unzip -q "$f"  -d "$SOURCE_DIR"                    2>>"$TOOLS_LOG" ;;
            *.whl)    unzip -q "$f"  -d "$SOURCE_DIR"                    2>>"$TOOLS_LOG" ;;
        esac
    done
    ok "Package extracted to isolated temp dir"
fi

PY_FILES=$(find "$SOURCE_DIR" -name "*.py" | wc -l | tr -d ' ')
log "Python files found: $PY_FILES"
divider

# ==============================================================================
#  STEP 3: PyPI Metadata & Typosquatting Signals
# ==============================================================================
section "STEP 3: Package Metadata & Typosquatting Analysis"

python3_run - <<PYEOF 2>/dev/null | tee -a "$REPORT_TXT" || true
import urllib.request, json, datetime

pkg = "$PACKAGE_NAME"
try:
    url = f"https://pypi.org/pypi/{pkg}/json"
    with urllib.request.urlopen(url, timeout=10) as r:
        data = json.load(r)
except Exception as e:
    print(f"  [skip] PyPI metadata unavailable: {e}")
    with open("$PYPI_META_JSON", "w") as f:
        json.dump({"pypi_info": {}, "metadata_flags": []}, f)
    raise SystemExit(0)

info = data["info"]
releases = data["releases"]
all_versions = list(releases.keys())
latest = info["version"]

print(f"  Package Name     : {info['name']}")
print(f"  Latest Version   : {latest}")
print(f"  Author           : {info['author']} <{info.get('author_email','?')}>")
print(f"  License          : {info.get('license','?')}")
print(f"  Summary          : {info.get('summary','?')[:80]}")
print(f"  Home Page        : {info.get('home_page','?')}")
print(f"  Total Releases   : {len(all_versions)}")
print(f"  Requires Python  : {info.get('requires_python','?')}")

# Flags
flags = []
if len(all_versions) <= 1:
    flags.append("TYPOSQUATTING RISK: Only 1 release (very new or copied name)")
if not info.get("license"):
    flags.append("No license declared")
if not info.get("home_page") and not info.get("project_url"):
    flags.append("No home page / repository link")
if info.get("author","").strip() == "":
    flags.append("No author declared")

# Dependency list
deps = info.get("requires_dist") or []
print(f"\n  Declared dependencies ({len(deps)}):")
for d in deps[:15]:
    print(f"    • {d}")
if len(deps) > 15:
    print(f"    … and {len(deps)-15} more")

if flags:
    print("\n  ⚠  Metadata Warnings:")
    for f in flags:
        print(f"    ! {f}")
else:
    print("\n  ✓ Metadata looks healthy")

with open("$PYPI_META_JSON", "w") as f:
    json.dump({
        "pypi_info": {
            "name": info.get("name"),
            "version": latest,
            "author": info.get("author"),
            "license": info.get("license"),
            "summary": info.get("summary"),
            "home_page": info.get("home_page"),
            "total_releases": len(all_versions),
            "requires_python": info.get("requires_python"),
            "requires_dist": deps,
        },
        "metadata_flags": flags,
    }, f)
PYEOF

# ==============================================================================
#  STEP 4: setup.py / pyproject.toml Install-Hook Analysis
# ==============================================================================
section "STEP 4: Install-Hook Analysis (setup.py / pyproject.toml)"

analyze_install_hooks() {
    local file="$1"
    local label="$2"
    local rel="${file#"$SOURCE_DIR"/}"

    declare -a HOOK_PATTERNS=(
        "cmdclass"
        "post_install"
        "pre_install"
        "install_requires.*exec"
        "os\.system"
        "os\.popen"
        "subprocess"
        "eval("
        "exec("
        "__import__"
        "base64"
        "urllib\.request"
        "requests\."
        "socket\."
        "pty\."
    )

    local found=0
    for p in "${HOOK_PATTERNS[@]}"; do
        if grep -qP "$p" "$file" 2>/dev/null; then
            high_f "${label}: suspicious pattern → ${p}"
            found=1
            local match_line match_content
            match_line=$(grep -nP "$p" "$file" 2>/dev/null | head -1 | cut -d: -f1)
            match_content=$(grep -m1 -P "$p" "$file" 2>/dev/null | sed -e 's/^[[:space:]]*//')
            record_finding "install-hook" "HIGH" "$p" "${label}: suspicious install-hook pattern" \
                "$rel" "${match_line:-}" "${match_content:-}"
        fi
    done
    [[ $found -eq 0 ]] && ok "${label}: no suspicious install-hook patterns"
}

[[ -f "$SOURCE_DIR/setup.py" ]]      && analyze_install_hooks "$SOURCE_DIR/setup.py"      "setup.py"
[[ -f "$SOURCE_DIR/pyproject.toml" ]] && analyze_install_hooks "$SOURCE_DIR/pyproject.toml" "pyproject.toml"
[[ -f "$SOURCE_DIR/setup.cfg" ]]     && analyze_install_hooks "$SOURCE_DIR/setup.cfg"     "setup.cfg"

if [[ ! -f "$SOURCE_DIR/setup.py" && ! -f "$SOURCE_DIR/pyproject.toml" && ! -f "$SOURCE_DIR/setup.cfg" ]]; then
    warn "No setup.py / pyproject.toml / setup.cfg found — package structure unclear"
fi

# ==============================================================================
#  STEP 5: Obfuscation & Malware Pattern Detection
# ==============================================================================
section "STEP 5: Obfuscation & Malware Patterns"

declare -A OBF_PATTERNS=(
    ["eval("]="eval() — arbitrary code execution"
    ["exec(compile("]="exec(compile()) — classic obfuscation"
    ["base64.b64decode"]="Base64 decode (check if decoded payload is eval'd)"
    ["marshal.loads"]="marshal.loads — binary bytecode injection"
    ["pickle.loads"]="pickle.loads — unsafe deserialisation"
    ["__import__("]="Dynamic import — string-based module loading"
    ["compile("]="compile() — runtime code generation"
    ["ctypes.cdll"]="ctypes.cdll — native shared-library loading"
    ["ctypes.CDLL"]="ctypes.CDLL — native shared-library loading"
    ["sys.modules\["]="sys.modules manipulation — module injection"
    ["importlib.import_module"]="importlib import — dynamic loading"
    ["zlib.decompress"]="zlib.decompress — compressed payload"
    ["gzip.decompress"]="gzip.decompress — compressed payload"
)

OBF_FOUND=0
for pat in "${!OBF_PATTERNS[@]}"; do
    hits=$(rg_scan "$pat" "$SOURCE_DIR")
    if [[ -n "$hits" ]]; then
        high_f "${OBF_PATTERNS[$pat]}"
        echo "$hits" | sed 's/^/    /' | tee -a "$REPORT_TXT"
        record_hits "obfuscation" "HIGH" "$pat" "${OBF_PATTERNS[$pat]}" "$hits"
        OBF_FOUND=1
    fi
done
[[ $OBF_FOUND -eq 0 ]] && ok "No obvious obfuscation patterns detected"

# ==============================================================================
#  STEP 6: Network & Data Exfiltration Analysis
# ==============================================================================
section "STEP 6: Network Activity & Exfiltration Detection"

declare -A NET_PATTERNS=(
    ["socket.socket("]="Raw socket — direct TCP/UDP connection"
    ["socket.connect("]="Socket connect — outbound connection"
    ["requests.post("]="HTTP POST — potential data exfiltration"
    ["requests.put("]="HTTP PUT — potential data upload"
    ["urllib.request.urlopen"]="urllib URL open"
    ["http.client.HTTPSConnection"]="Direct HTTPS connection"
    ["ftplib.FTP("]="FTP connection"
    ["smtplib.SMTP("]="SMTP — email sending"
    ["imaplib.IMAP4"]="IMAP — email reading"
    ["paramiko"]="Paramiko — SSH client"
    ["telnetlib"]="Telnet connection"
    ["websocket"]="WebSocket connection"
    ["dns.resolver"]="DNS lookup"
    ["boto3"]="AWS SDK — cloud resource access"
    ["subprocess.*curl\|subprocess.*wget\|subprocess.*nc "]="Shell network tools"
)

NET_FOUND=0
for pat in "${!NET_PATTERNS[@]}"; do
    hits=$(rg_scan "$pat" "$SOURCE_DIR" | head -3)
    if [[ -n "$hits" ]]; then
        warn "${NET_PATTERNS[$pat]} ($pat)"
        echo "$hits" | sed 's/^/    /' | tee -a "$REPORT_TXT"
        record_hits "network" "MEDIUM" "$pat" "${NET_PATTERNS[$pat]}" "$hits"
        NET_FOUND=1
    fi
done

# Hardcoded IPs (exclude localhost / CIDR notation docs)
if cmd_exists rg; then
    HARDCODED_IPS=$(rg --no-heading -n \
        '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' \
        "$SOURCE_DIR" --glob "*.py" 2>/dev/null \
        | grep -Ev '127\.0\.0\.1|0\.0\.0\.0|255\.|localhost|#' \
        | head -10 || true)
else
    HARDCODED_IPS=$(grep -rEn \
        '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' \
        "$SOURCE_DIR" --include="*.py" 2>/dev/null \
        | grep -Ev '127\.0\.0\.1|0\.0\.0\.0|255\.|localhost|#' \
        | head -10 || true)
fi
if [[ -n "$HARDCODED_IPS" ]]; then
    high_f "Hardcoded IP addresses found:"
    echo "$HARDCODED_IPS" | sed 's/^/    /' | tee -a "$REPORT_TXT"
    record_hits "network" "HIGH" "hardcoded-ip" "Hardcoded IP address" "$HARDCODED_IPS"
fi

[[ $NET_FOUND -eq 0 && -z "${HARDCODED_IPS:-}" ]] && ok "No suspicious outbound network patterns found"

# ==============================================================================
#  STEP 7: Filesystem Snooping & Credential Access
# ==============================================================================
section "STEP 7: Filesystem Snooping & Credential Access"

# Critical patterns → CRITICAL severity
declare -A CRIT_FS_PATTERNS=(
    ["/etc/shadow"]="Reading /etc/shadow — password hash theft"
    ["/.ssh/id_"]="Reading SSH private keys"
    ["/.ssh/authorized_keys"]="Reading SSH authorized_keys"
    ["/.aws/credentials"]="Reading AWS credentials file"
    ["/.aws/config"]="Reading AWS config"
    ["GOOGLE_APPLICATION_CREDENTIALS"]="Google service account key access"
    ["/root/."]="Accessing /root/ directory"
)

# High patterns
declare -A HIGH_FS_PATTERNS=(
    ["/etc/passwd"]="Reading /etc/passwd — user enumeration"
    ["/.docker/config"]="Reading Docker credentials"
    ["/.kube/config"]="Reading Kubernetes config"
    ["/.npmrc"]="Reading npm credentials"
    ["/.pypirc"]="Reading PyPI credentials"
    ["/.netrc"]="Reading netrc (FTP/HTTP credentials)"
    ["/proc/self/"]="Reading /proc/self — process introspection"
    ["PRIVATE_KEY\|private_key"]="Searching for private key content"
)

# Medium patterns
declare -A MED_FS_PATTERNS=(
    ["os.environ"]="Reading environment variables (may include secrets)"
    ["os.getenv("]="Reading environment variables"
    ["glob.glob.*password\|glob.glob.*secret\|glob.glob.*token"]="Searching filesystem for secrets"
    ["keyring"]="Accessing system keyring"
    ["pathlib.Path.*home()"]="Accessing home directory"
)

FS_FOUND=0
for pat in "${!CRIT_FS_PATTERNS[@]}"; do
    hits=$(rg_scan "$pat" "$SOURCE_DIR" | head -3)
    if [[ -n "$hits" ]]; then
        crit_f "${CRIT_FS_PATTERNS[$pat]}"
        echo "$hits" | sed 's/^/    /' | tee -a "$REPORT_TXT"
        record_hits "filesystem" "CRITICAL" "$pat" "${CRIT_FS_PATTERNS[$pat]}" "$hits"
        FS_FOUND=1
    fi
done
for pat in "${!HIGH_FS_PATTERNS[@]}"; do
    hits=$(rg_scan "$pat" "$SOURCE_DIR" | head -3)
    if [[ -n "$hits" ]]; then
        high_f "${HIGH_FS_PATTERNS[$pat]}"
        echo "$hits" | sed 's/^/    /' | tee -a "$REPORT_TXT"
        record_hits "filesystem" "HIGH" "$pat" "${HIGH_FS_PATTERNS[$pat]}" "$hits"
        FS_FOUND=1
    fi
done
for pat in "${!MED_FS_PATTERNS[@]}"; do
    hits=$(rg_scan "$pat" "$SOURCE_DIR" | head -3)
    if [[ -n "$hits" ]]; then
        warn "${MED_FS_PATTERNS[$pat]}"
        echo "$hits" | sed 's/^/    /' | tee -a "$REPORT_TXT"
        record_hits "filesystem" "MEDIUM" "$pat" "${MED_FS_PATTERNS[$pat]}" "$hits"
        FS_FOUND=1
    fi
done

[[ $FS_FOUND -eq 0 ]] && ok "No credential/filesystem snooping patterns detected"

# ==============================================================================
#  STEP 8: Hardcoded Secrets (detect-secrets)
# ==============================================================================
section "STEP 8: Hardcoded Secrets Detection"

log "Running detect-secrets …"
SECRETS_JSON="$SCAN_ROOT/secrets.json"
cd "$SOURCE_DIR"
"$DET_SECRETS" scan --all-files --force-use-all-plugins \
    2>>"$TOOLS_LOG" > "$SECRETS_JSON" || true
cd - >/dev/null

python3_run - <<PYEOF 2>/dev/null | tee -a "$REPORT_TXT"
import json

with open("$SECRETS_JSON") as f:
    data = json.load(f)

results = data.get("results", {})
total = sum(len(v) for v in results.values())

if total == 0:
    print("  ✓ detect-secrets: No hardcoded secrets found")
else:
    print(f"  ✗ detect-secrets: {total} potential secret(s) found!\n")
    for fname, secrets in results.items():
        for s in secrets:
            print(f"    [{s['type']}] {fname} : line {s['line_number']}")
PYEOF

# ==============================================================================
#  STEP 8b: Git History Secret Scan — gitleaks
#  WHY THIS MATTERS: detect-secrets only sees the current file tree.
#  Developers often commit secrets, realise, delete the file — but the secret
#  lives forever in git history. gitleaks traverses every commit.
# ==============================================================================
section "STEP 8b: Git History Secret Scan — gitleaks"

if ! $HAS_GITLEAKS; then
    warn "gitleaks not installed — SKIPPING git history scan (biggest blind spot)"
    echo "    This step catches secrets deleted from code but still in git log." | tee -a "$REPORT_TXT"
    echo "    Install gitleaks and re-run for a complete scan." | tee -a "$REPORT_TXT"
else
    GITLEAKS_EXIT=0

    # If we have a real git repo (GitHub input or PyPI pkg with embedded .git)
    if [[ -d "$SOURCE_DIR/.git" ]]; then
        log "Running gitleaks on full git history …"
        gitleaks detect \
            --source "$SOURCE_DIR" \
            --report-format json \
            --report-path "$GITLEAKS_JSON" \
            --no-banner \
            --exit-code 0 \
            2>>"$TOOLS_LOG" || GITLEAKS_EXIT=$?

        python3_run - <<PYEOF 2>/dev/null | tee -a "$REPORT_TXT"
import json, os

report_path = "$GITLEAKS_JSON"
if not os.path.exists(report_path):
    print("  ✓ gitleaks: report file not created — no leaks found in history")
    raise SystemExit(0)

try:
    with open(report_path) as f:
        content = f.read().strip()
    if not content or content == "null":
        print("  ✓ gitleaks: No secrets found in git commit history")
        raise SystemExit(0)
    leaks = json.loads(content)
    if not leaks:
        print("  ✓ gitleaks: No secrets found in git commit history")
        raise SystemExit(0)
except json.JSONDecodeError:
    print("  ✓ gitleaks: No leaks detected (empty report)")
    raise SystemExit(0)

print(f"  ✗ gitleaks: {len(leaks)} secret leak(s) found in git HISTORY!\n")
for leak in leaks[:15]:
    rule    = leak.get('RuleID', '?')
    desc    = leak.get('Description', '?')
    file_   = leak.get('File', '?')
    line    = leak.get('StartLine', '?')
    commit  = leak.get('Commit', '?')[:8]
    author  = leak.get('Author', '?')
    date_   = leak.get('Date', '?')[:10]
    match   = leak.get('Match', '')[:60]
    print(f"  [{rule}] {desc}")
    print(f"    File   : {file_}:{line}")
    print(f"    Commit : {commit}  Author: {author}  Date: {date_}")
    print(f"    Match  : {match}…")
    print()
if len(leaks) > 15:
    print(f"  … and {len(leaks)-15} more leaks. See: $GITLEAKS_JSON")
PYEOF
    else
        log "No .git directory found (PyPI tarball source — history scan skipped)"
        log "For full history scan, pass the GitHub URL instead of the PyPI name."
    fi
fi

# ==============================================================================
#  STEP 9: SAST — Bandit
# ==============================================================================
section "STEP 9: SAST — Bandit"

log "Running Bandit SAST (all severity levels) …"
BANDIT_JSON="$SCAN_ROOT/bandit.json"

"$BANDIT" -r "$SOURCE_DIR" \
    --format json \
    --output "$BANDIT_JSON" \
    --severity-level low \
    --confidence-level low \
    2>>"$TOOLS_LOG" || true   # bandit exits non-zero when issues found

python3_run - <<PYEOF 2>/dev/null | tee -a "$REPORT_TXT"
import json

try:
    with open("$BANDIT_JSON") as f:
        data = json.load(f)
except Exception as e:
    print(f"  [skip] Bandit output unreadable: {e}")
    raise SystemExit(0)

metrics  = data.get("metrics", {}).get("_totals", {})
results  = data.get("results", [])
h = int(metrics.get("SEVERITY.HIGH",   0))
m = int(metrics.get("SEVERITY.MEDIUM", 0))
l = int(metrics.get("SEVERITY.LOW",    0))

print(f"  Files scanned : {int(metrics.get('loc', 0))}")
print(f"  Issues total  : {len(results)}  (HIGH={h}  MEDIUM={m}  LOW={l})")

if results:
    print(f"\n  Top findings:")
    for r in sorted(results, key=lambda x: (x['issue_severity'], x['issue_confidence']), reverse=True)[:20]:
        sev  = r['issue_severity']
        conf = r['issue_confidence']
        test = r['test_id']
        msg  = r['issue_text'][:90]
        path = r['filename'].replace("$SOURCE_DIR/", "")
        line = r['line_number']
        print(f"    [{sev}/{conf}] {test} — {msg}")
        print(f"        {path}:{line}")
else:
    print("  ✓ Bandit: no issues found")
PYEOF

# ==============================================================================
#  STEP 10: SAST — Semgrep
# ==============================================================================
section "STEP 10: SAST — Semgrep"

log "Running Semgrep — auto + p/python + p/security-audit + p/secrets …"
log "  (--config=auto from friend's playbook adopted: broader language coverage)"
SEMGREP_JSON="$SCAN_ROOT/semgrep.json"

"$SEMGREP" scan \
    --config "auto" \
    --config "p/python" \
    --config "p/security-audit" \
    --config "p/secrets" \
    --json \
    --output "$SEMGREP_JSON" \
    --quiet \
    "$SOURCE_DIR" \
    2>>"$TOOLS_LOG" || true

python3_run - <<PYEOF 2>/dev/null | tee -a "$REPORT_TXT"
import json

try:
    with open("$SEMGREP_JSON") as f:
        data = json.load(f)
except Exception as e:
    print(f"  [skip] Semgrep output unreadable: {e}")
    raise SystemExit(0)

results = data.get("results", [])
sev_map = {}
for r in results:
    sev = r.get("extra", {}).get("severity", "INFO")
    sev_map[sev] = sev_map.get(sev, 0) + 1

print(f"  Total findings: {len(results)}")
for sev in ("ERROR", "WARNING", "INFO"):
    if sev in sev_map:
        print(f"    {sev}: {sev_map[sev]}")

if results:
    print(f"\n  Findings (top 20):")
    for r in results[:20]:
        extra = r.get("extra", {})
        sev   = extra.get("severity", "INFO")
        msg   = extra.get("message", r.get("check_id",""))[:90]
        path  = r.get("path","").replace("$SOURCE_DIR/","")
        line  = r.get("start",{}).get("line","?")
        rule  = r.get("check_id","?").split(".")[-1]
        print(f"    [{sev}] {rule} — {msg}")
        print(f"        {path}:{line}")
else:
    print("  ✓ Semgrep: no findings")
PYEOF

# ==============================================================================
#  STEP 11: CVE Scan — pip-audit
# ==============================================================================
section "STEP 11: CVE Scan — pip-audit"

log "Installing package into venv to resolve full dependency tree …"
pip_run install --quiet "$PACKAGE_NAME" 2>>"$TOOLS_LOG" || \
    pip_run install --quiet -e "$SOURCE_DIR" 2>>"$TOOLS_LOG" || \
    warn "Could not install package — CVE scan will be limited to declared deps"

log "Running pip-audit against installed dependency tree …"
PIP_AUDIT_JSON="$SCAN_ROOT/pip_audit.json"

"$PIP_AUDIT" \
    --format json \
    --output "$PIP_AUDIT_JSON" \
    2>>"$TOOLS_LOG" || true

python3_run - <<PYEOF 2>/dev/null | tee -a "$REPORT_TXT"
import json

try:
    with open("$PIP_AUDIT_JSON") as f:
        data = json.load(f)
except Exception as e:
    print(f"  [skip] pip-audit output unreadable: {e}")
    raise SystemExit(0)

deps  = data.get("dependencies", [])
vulns = [d for d in deps if d.get("vulns")]

print(f"  Dependencies scanned : {len(deps)}")
print(f"  Vulnerable packages  : {len(vulns)}")

for d in vulns:
    print(f"\n  ✗ {d['name']} {d['version']}")
    for v in d["vulns"]:
        print(f"      CVE/ID   : {v['id']}")
        print(f"      Summary  : {v.get('description','?')[:110]}")
        fixes = v.get('fix_versions', [])
        print(f"      Fix in   : {fixes if fixes else 'No fix available'}")

if not vulns:
    print("  ✓ pip-audit: No known CVEs found")
PYEOF

# ==============================================================================
#  STEP 12: CVE Scan — Safety
# ==============================================================================
section "STEP 12: CVE Scan — Safety"

log "Running Safety check …"
SAFETY_OUT="$SCAN_ROOT/safety.txt"

"$SAFETY" check --full-report 2>>"$TOOLS_LOG" > "$SAFETY_OUT" || true

python3_run - <<PYEOF 2>/dev/null | tee -a "$REPORT_TXT"
import re

try:
    with open("$SAFETY_OUT") as f:
        content = f.read()
except Exception as e:
    print(f"  [skip] Safety output unreadable: {e}")
    raise SystemExit(0)

if "No known security vulnerabilities" in content or "no issues found" in content.lower():
    print("  ✓ Safety: No known vulnerabilities")
elif "vulnerabilit" in content.lower():
    print("  Safety report (excerpt):")
    for line in content.splitlines()[:30]:
        print(f"    {line}")
else:
    print("  Safety: scan complete (check full output for details)")
    print(f"  (Saved to: $SAFETY_OUT)")
PYEOF

# ==============================================================================
#  STEP 13: __init__.py Side-Effect Analysis
# ==============================================================================
section "STEP 13: __init__.py Side-Effect Analysis"

log "Checking __init__.py files for top-level executable side-effects …"

find "$SOURCE_DIR" -name "__init__.py" | while IFS= read -r init_file; do
    rel_path="${init_file#$SOURCE_DIR/}"
    python3_run - <<PYEOF 2>/dev/null | tee -a "$REPORT_TXT"
import ast, json, os

path = "$init_file"
rel  = "$rel_path"

try:
    with open(path) as f:
        src = f.read()
    tree = ast.parse(src, filename=path)
except SyntaxError as e:
    print(f"  [warn] {rel}: syntax error — {e}")
    raise SystemExit(0)
except Exception:
    raise SystemExit(0)

side_effects = []
CALL_ATTRS = {
    'connect','get','post','put','delete','send','system','popen',
    'urlopen','urlretrieve','socket','exec','eval'
}
DANGER_NAMES = {'exec','eval','compile','__import__'}

for node in ast.walk(tree):
    if isinstance(node, ast.Call):
        func = node.func
        if isinstance(func, ast.Name) and func.id in DANGER_NAMES:
            side_effects.append((node.lineno, f"{func.id}()"))
        elif isinstance(func, ast.Attribute) and func.attr in CALL_ATTRS:
            side_effects.append((node.lineno, f".{func.attr}()"))

if side_effects:
    print(f"  ⚠  {rel}: executable side-effects on import:")
    for lineno, se in side_effects[:8]:
        print(f"      line {lineno}: {se}")
    jsonl = os.environ.get("CUSTOM_FINDINGS_JSONL")
    if jsonl:
        with open(jsonl, "a") as fh:
            for lineno, se in side_effects[:8]:
                fh.write(json.dumps({
                    "category": "obfuscation",
                    "severity": "MEDIUM",
                    "pattern": "init-side-effect",
                    "description": "Executable side-effect on import in __init__.py",
                    "file": rel,
                    "line_number": lineno,
                    "line_content": se,
                }) + "\n")
else:
    print(f"  ✓  {rel}: clean")
PYEOF
done

# ==============================================================================
#  STEP 14: Non-Python file audit (shell scripts, compiled binaries)
# ==============================================================================
section "STEP 14: Non-Python Suspicious File Audit"

log "Checking for shell scripts, compiled binaries, and suspicious extensions …"

SHELL_SCRIPTS=$(find "$SOURCE_DIR" -name "*.sh" -o -name "*.bash" 2>/dev/null | head -20 || true)
ELF_BINS=$(find "$SOURCE_DIR" -type f -exec file {} \; 2>/dev/null \
    | grep -i "ELF\|Mach-O\|PE32\|executable" | head -10 || true)
UNUSUAL=$(find "$SOURCE_DIR" -type f \( \
    -name "*.so" -o -name "*.dll" -o -name "*.dylib" -o \
    -name "*.pyc" -o -name "*.pyo" \) 2>/dev/null | head -20 || true)

if [[ -n "$SHELL_SCRIPTS" ]]; then
    warn "Shell scripts found (review them manually):"
    echo "$SHELL_SCRIPTS" | sed "s|$SOURCE_DIR/||" | sed 's/^/    /' | tee -a "$REPORT_TXT"
    while IFS= read -r sfile; do
        [[ -z "$sfile" ]] && continue
        record_finding "other" "LOW" "shell-script" "Shell script present — review manually" \
            "${sfile#"$SOURCE_DIR"/}" "" ""
    done <<< "$SHELL_SCRIPTS"
fi
if [[ -n "$ELF_BINS" ]]; then
    high_f "Compiled native binaries found:"
    echo "$ELF_BINS" | sed "s|$SOURCE_DIR/||" | sed 's/^/    /' | tee -a "$REPORT_TXT"
    while IFS= read -r bline; do
        [[ -z "$bline" ]] && continue
        bpath="${bline%%:*}"
        record_finding "other" "HIGH" "native-binary" "Compiled native binary found" \
            "${bpath#"$SOURCE_DIR"/}" "" "$bline"
    done <<< "$ELF_BINS"
fi
if [[ -n "$UNUSUAL" ]]; then
    warn "Compiled Python or native extension files (.so/.dll/.dylib):"
    echo "$UNUSUAL" | sed "s|$SOURCE_DIR/||" | sed 's/^/    /' | tee -a "$REPORT_TXT"
    while IFS= read -r ufile; do
        [[ -z "$ufile" ]] && continue
        record_finding "other" "MEDIUM" "compiled-extension" "Compiled/extension file present" \
            "${ufile#"$SOURCE_DIR"/}" "" ""
    done <<< "$UNUSUAL"
fi
[[ -z "$SHELL_SCRIPTS$ELF_BINS$UNUSUAL" ]] && ok "No shell scripts or compiled binaries found"

# ==============================================================================
#  STEP 14b: Consolidate tool findings into verdict scoring
#  WHY: Bandit/Semgrep/pip-audit/detect-secrets/gitleaks findings were only
#  ever printed to the report — they never fed the CRITICAL/HIGH/MEDIUM/LOW
#  counters used for the final verdict, so a package riddled with CVEs or a
#  Bandit-flagged shell injection could still score "LIKELY SAFE". Severity
#  mapping mirrors reporter/generate_report.py so the dashboard score card
#  matches the per-tool badges shown in the HTML report.
# ==============================================================================
TOOL_COUNTS_FILE="$SCAN_ROOT/tool_severity_counts.txt"

python3_run - <<PYEOF 2>>"$TOOLS_LOG" || true
import json

def load(path, default):
    try:
        with open(path) as f:
            text = f.read().strip()
        return json.loads(text) if text and text != "null" else default
    except Exception:
        return default

c = h = m = l = 0

bandit = load("$BANDIT_JSON", {"results": []})
for r in bandit.get("results", []):
    sev = str(r.get("issue_severity", "")).upper()
    if sev == "HIGH":     h += 1
    elif sev == "MEDIUM": m += 1
    elif sev == "LOW":    l += 1

semgrep = load("$SEMGREP_JSON", {"results": []})
for r in semgrep.get("results", []):
    sev = str(r.get("extra", {}).get("severity", "")).upper()
    if sev == "ERROR":     h += 1
    elif sev == "WARNING": m += 1
    else:                  l += 1

secrets = load("$SECRETS_JSON", {"results": {}})
h += sum(len(v) for v in secrets.get("results", {}).values())

gitleaks = load("$GITLEAKS_JSON", [])
if isinstance(gitleaks, list):
    c += len(gitleaks)

pip_audit = load("$PIP_AUDIT_JSON", {"dependencies": []})
h += sum(len(d.get("vulns", [])) for d in pip_audit.get("dependencies", []) if d.get("vulns"))

with open("$TOOL_COUNTS_FILE", "w") as f:
    f.write(f"{c} {h} {m} {l}\n")
PYEOF

if [[ -f "$TOOL_COUNTS_FILE" ]]; then
    IFS=' ' read -r TOOL_C TOOL_H TOOL_M TOOL_L < "$TOOL_COUNTS_FILE"
    CRITICAL=$((CRITICAL + ${TOOL_C:-0}))
    HIGH=$((HIGH + ${TOOL_H:-0}))
    MEDIUM=$((MEDIUM + ${TOOL_M:-0}))
    LOW=$((LOW + ${TOOL_L:-0}))
fi

# ==============================================================================
#  FINAL: Verdict
# ==============================================================================
section "FINAL VERDICT"

python3_run - <<PYEOF | tee -a "$REPORT_TXT"
import json

C = $CRITICAL
H = $HIGH
M = $MEDIUM
L = $LOW
T = C + H + M + L

bar = "━" * 56

print(bar)
print(f"  ISSUE SUMMARY")
print(bar)
print(f"  {'Critical':12}: {C:>4}")
print(f"  {'High':12}: {H:>4}")
print(f"  {'Medium':12}: {M:>4}")
print(f"  {'Low':12}: {L:>4}")
print(f"  {'Total':12}: {T:>4}")
print(bar)

if C > 0:
    verdict_emoji = "🚨"
    verdict_text  = "AVOID — CRITICAL SECURITY RISKS DETECTED"
    explain = (
        "One or more CRITICAL severity issues were found. "
        "This module should NOT be used until those are resolved. "
        "Review the CRITICAL findings above immediately."
    )
elif H >= 3:
    verdict_emoji = "❌"
    verdict_text  = "AVOID — MULTIPLE HIGH SEVERITY ISSUES"
    explain = (
        f"{H} HIGH severity issues were detected. "
        "Strong recommendation to avoid this package. "
        "If required, consult your security team before proceeding."
    )
elif H > 0 or M >= 5:
    verdict_emoji = "⚠️"
    verdict_text  = "USE WITH CAUTION — REVIEW FINDINGS BEFORE DEPLOYING"
    explain = (
        "Several security concerns were identified. "
        "Manually review each HIGH/MEDIUM finding. "
        "Consider sandboxing or network-egress restrictions on the host."
    )
elif M > 0 or L > 0:
    verdict_emoji = "ℹ️"
    verdict_text  = "LOW RISK — MINOR ISSUES, STANDARD DUE DILIGENCE ADVISED"
    explain = (
        "Only low/medium informational issues found. "
        "Apply standard security practices: venv isolation, "
        "principle of least privilege, and monitor runtime behaviour."
    )
else:
    verdict_emoji = "✅"
    verdict_text  = "LIKELY SAFE — No significant issues detected"
    explain = (
        "No critical, high, or medium issues were found by automated tools. "
        "Automated scanning has limits — always combine with manual review "
        "and runtime monitoring in production."
    )

verdict = f"{verdict_emoji}  {verdict_text}"
print(f"\n  VERDICT: {verdict}")
print(f"\n  {explain}\n")
print(bar)
print()
print("  Recommendations:")
print("  1. Always install in a virtual environment (never system Python)")
print("  2. Use network egress firewall rules on the server")
print("  3. Run the module with least-privilege OS user")
print("  4. Monitor outbound connections at runtime (e.g. strace / eBPF)")
print("  5. Pin the exact version in requirements.txt + verify hash")
print("     (pip install --require-hashes)")
print("  6. Re-run this scanner after every version upgrade")
print(bar)

with open("$VERDICT_JSON", "w") as f:
    json.dump({
        "verdict": verdict_text,
        "verdict_emoji": verdict_emoji,
        "verdict_sub": explain,
        "score": {"critical": C, "high": H, "medium": M, "low": L},
    }, f)
PYEOF

# ==============================================================================
#  Generate HTML Report (optional --html flag)
#  Assembles meta.json from the structured data collected during the scan,
#  then hands everything off to reporter/generate_report.py to build a full
#  dashboard-style report (tables, severity badges, filters, GitHub deep
#  links) instead of dumping the raw text log into a <pre> tag.
# ==============================================================================
if $GENERATE_HTML; then
    log "Generating HTML report …"

    FINISHED_EPOCH=$(date +%s)
    DURATION_SECONDS=$((FINISHED_EPOCH - START_EPOCH))
    FINISHED_AT_ISO=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    META_JSON="$SCAN_ROOT/meta.json"

    RUN_ID="$TIMESTAMP" TARGET_URL="$TARGET_URL" PACKAGE_NAME_ENV="$PACKAGE_NAME" \
    STARTED_AT="$STARTED_AT_ISO" FINISHED_AT="$FINISHED_AT_ISO" DURATION_SECONDS="$DURATION_SECONDS" \
    IS_GITHUB="$IS_GITHUB" GITLEAKS_AVAILABLE="$HAS_GITLEAKS" \
    PYPI_META_JSON="$PYPI_META_JSON" VERDICT_JSON="$VERDICT_JSON" \
    META_JSON_OUT="$META_JSON" \
    python3_run -c "
import json, os

def load_json(path, default):
    try:
        with open(path) as f:
            text = f.read().strip()
        return json.loads(text) if text else default
    except Exception:
        return default

pypi_meta = load_json(os.environ.get('PYPI_META_JSON', ''), {})
verdict   = load_json(os.environ.get('VERDICT_JSON', ''), {})

custom_findings = []
jsonl = os.environ.get('CUSTOM_FINDINGS_JSONL', '')
if jsonl and os.path.exists(jsonl):
    with open(jsonl) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                custom_findings.append(json.loads(line))
            except Exception:
                pass

meta = {
    'run_id': os.environ.get('RUN_ID', 'unknown'),
    'target': os.environ.get('TARGET_URL', ''),
    'package_name': os.environ.get('PACKAGE_NAME_ENV', ''),
    'started_at': os.environ.get('STARTED_AT', ''),
    'finished_at': os.environ.get('FINISHED_AT', ''),
    'duration_seconds': int(os.environ.get('DURATION_SECONDS', '0') or 0),
    'scanner_version': '2.1',
    'is_github': os.environ.get('IS_GITHUB', '') == 'true',
    'tools': {'gitleaks_available': os.environ.get('GITLEAKS_AVAILABLE', '') == 'true'},
    'verdict': verdict.get('verdict', 'UNKNOWN'),
    'verdict_emoji': verdict.get('verdict_emoji', '🔍'),
    'verdict_sub': verdict.get('verdict_sub', ''),
    'score': verdict.get('score', {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}),
    'pypi_info': pypi_meta.get('pypi_info', {}),
    'metadata_flags': pypi_meta.get('metadata_flags', []),
    'custom_findings': custom_findings,
}

with open(os.environ['META_JSON_OUT'], 'w') as f:
    json.dump(meta, f)
"

    REPORTER_DIR="${PYSENTINEL_REPORTER:-$SCRIPT_REPORTER_DIR}"

    if [[ -z "$REPORTER_DIR" || ! -f "$REPORTER_DIR/generate_report.py" ]]; then
        warn "Reporter not found (looked in: ${REPORTER_DIR:-<unset>}) — skipping HTML report"
    elif python3_run "$REPORTER_DIR/generate_report.py" \
            --meta       "$META_JSON" \
            --bandit     "$BANDIT_JSON" \
            --semgrep    "$SEMGREP_JSON" \
            --gitleaks   "$GITLEAKS_JSON" \
            --secrets    "$SECRETS_JSON" \
            --pip-audit  "$PIP_AUDIT_JSON" \
            --output     "$REPORT_HTML" \
            2>>"$TOOLS_LOG"; then
        ok "HTML report → $REPORT_HTML"
    else
        warn "HTML report generation failed — see $TOOLS_LOG"
    fi
fi

echo ""
echo -e "${GRN}${BOLD}Report saved → ${REPORT_TXT}${NC}"
$GENERATE_HTML && echo -e "${GRN}${BOLD}HTML Report  → ${REPORT_HTML}${NC}"
echo -e "${CYN}Temp scan directory will be deleted automatically on exit.${NC}"
echo ""
