#!/usr/bin/env bash
# unified_hybrid_recon.sh
# Complete Recon + Hybrid Parallel Bug-Hunt in one script
#
# Usage: ./unified_hybrid_recon.sh example.com [--parallel]

set -uo pipefail

TARGET="${1:-}"
MODE="${2:-}"

[[ -z "$TARGET" ]] && { echo "Usage: $0 <domain> [--parallel]"; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RECON_SCRIPT="${SCRIPT_DIR}/recon_full.sh"
BUG_SCRIPT="${SCRIPT_DIR}/bughunt_auto_parallel.sh"

CORES=$( (nproc 2>/dev/null || sysctl -n hw.logicalcpu 2>/dev/null) || echo 2 )
export THREADS=$(( CORES * 75 ))
export RATE=$(( CORES * 200 ))
export NUCLEI_RATELIMIT="$RATE"

log(){ echo -e "\\033[1;34m[*]\\033[0m $*"; }
ok(){ echo -e "\\033[1;32m[OK]\\033[0m $*"; }
fail(){ echo -e "\\033[1;31m[FAIL]\\033[0m $*"; }

run(){ log "$*"; "$@" && ok "$*" || fail "$*"; }

log "Starting Unified Recon+BugHunt (Hybrid)"
log "Domain: $TARGET | Mode: ${MODE:---sequential}"

START=$(date +%s)

# 1. RECON
run "$RECON_SCRIPT" "$TARGET"
OUT_DIR=$(ls -td results_${TARGET}_* | head -n1 || true)
[[ -d "$OUT_DIR" ]] || { fail "Recon output dir missing"; exit 1; }

# 2. BUG-HUNT
if [[ "$MODE" == "--parallel" ]]; then
  run "$BUG_SCRIPT" "$OUT_DIR" --parallel
else
  run "$BUG_SCRIPT" "$OUT_DIR"
fi

END=$(date +%s)
ELAPSED=$((END - START))
log "All done in $(printf '%02dh:%02dm:%02ds' $((ELAPSED/3600)) $((ELAPSED%3600/60)) $((ELAPSED%60)))"
log "Check results: $OUT_DIR"
