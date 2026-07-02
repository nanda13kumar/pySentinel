#!/usr/bin/env bash
# ==============================================================================
#  scan.sh — PySentinel launcher
#  The ONLY command you need to run.
#
#  Usage:
#    ./scan.sh nsepython
#    ./scan.sh https://github.com/aeron7/nsepython
#    ./scan.sh requests --html
#
#  What it does automatically:
#    1. Enables BuildKit (fixes pip timeout via download cache)
#    2. Builds the Docker image if it doesn't exist yet (one-time, ~5 min)
#    3. Runs the scan in an isolated container
#    4. Saves the report to ./reports/
#    5. Removes the container when done
# ==============================================================================
set -euo pipefail

IMAGE="pysentinel:2.1"
REPORTS_DIR="$(pwd)/reports"
TARGET="${1:-}"
EXTRA_ARG="${2:-}"   # optional --html

# ── Colour helpers ─────────────────────────────────────────────────────────────
RED='\033[0;31m'; GRN='\033[0;32m'; CYN='\033[0;36m'; YEL='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${CYN}[pysentinel]${NC} $*"; }
ok()    { echo -e "${GRN}[pysentinel]${NC} $*"; }
err()   { echo -e "${RED}[pysentinel]${NC} $*" >&2; }
warn()  { echo -e "${YEL}[pysentinel]${NC} $*"; }

# ── Usage ──────────────────────────────────────────────────────────────────────
if [[ -z "$TARGET" || "$TARGET" == "--help" || "$TARGET" == "-h" ]]; then
    echo ""
    echo "  PySentinel v2.1 — Python Module Security Scanner"
    echo ""
    echo "  Usage:"
    echo "    ./scan.sh <pypi-package | github-url> [--html]"
    echo ""
    echo "  Examples:"
    echo "    ./scan.sh nsepython"
    echo "    ./scan.sh https://github.com/aeron7/nsepython"
    echo "    ./scan.sh requests --html"
    echo ""
    echo "  Reports are saved to: ./reports/"
    echo ""
    exit 0
fi

# ── Preflight: require docker ──────────────────────────────────────────────────
if ! command -v docker &>/dev/null; then
    err "Docker not found. Install from https://docs.docker.com/get-docker/"
    exit 1
fi

if ! docker info &>/dev/null 2>&1; then
    err "Docker daemon is not running. Start Docker Desktop and retry."
    exit 1
fi

# ── Enable BuildKit (the pip cache fix) ───────────────────────────────────────
export DOCKER_BUILDKIT=1
export BUILDKIT_PROGRESS=plain   # show full build output — no hidden timeouts

# ── Build image if not already built ──────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if docker image inspect "$IMAGE" &>/dev/null 2>&1; then
    ok "Image $IMAGE already built — skipping build"
else
    info "Building $IMAGE for the first time (one-time setup, ~5 minutes) …"
    info "BuildKit pip-cache is active: timeouts don't restart the download."
    echo ""
    docker build \
        --tag "$IMAGE" \
        --file "$SCRIPT_DIR/Dockerfile" \
        "$SCRIPT_DIR"
    echo ""
    ok "Image built successfully — future runs will be instant."
fi

# ── Create reports directory ───────────────────────────────────────────────────
mkdir -p "$REPORTS_DIR"

# ── Run the scan ──────────────────────────────────────────────────────────────
info "Starting scan: $TARGET"
echo ""

docker run \
    --rm \
    --name "pysentinel-$$" \
    --volume  "$REPORTS_DIR:/home/scanner/pysentinel_reports" \
    --cap-drop ALL \
    --security-opt no-new-privileges:true \
    --memory 1g \
    --cpus 2 \
    "$IMAGE" \
    "$TARGET" \
    ${EXTRA_ARG:+"$EXTRA_ARG"}

echo ""
ok "Scan complete. Reports saved to: $REPORTS_DIR"

# ── List generated report files ───────────────────────────────────────────────
LATEST=$(ls -t "$REPORTS_DIR"/pysentinel_*.txt 2>/dev/null | head -1 || true)
if [[ -n "$LATEST" ]]; then
    ok "Latest report: $LATEST"
fi
if [[ -n "$EXTRA_ARG" && "$EXTRA_ARG" == "--html" ]]; then
    LATEST_HTML=$(ls -t "$REPORTS_DIR"/pysentinel_*.html 2>/dev/null | head -1 || true)
    [[ -n "$LATEST_HTML" ]] && ok "HTML report:   $LATEST_HTML"
fi
