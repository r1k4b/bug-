#!/usr/bin/env bash
# recon_suite_v2.sh
# Resilient Recon + Bug‑Hunt – continues even if individual steps fail
#
# Usage: ./recon_suite_v2.sh <target-domain>
# Flags  : --help  (show help)
#
# Logs successes / failures and never quits unless user aborts.

###############################################################################
set -uo pipefail

CORES=$( (nproc 2>/dev/null || sysctl -n hw.logicalcpu 2>/dev/null) || echo 2 )
DEF_THREADS=$(( CORES * 75 ))
RATE_LIMIT=$(( CORES * 200 ))

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RECON_SCRIPT="${SCRIPT_DIR}/recon_full.sh"
BUG_SCRIPT="${SCRIPT_DIR}/bughunt_auto.sh"

usage(){ cat <<EOF
Resilient Recon Suite
Usage: $0 <domain>
Env   THREADS=n  RATE=n
EOF
exit 0; }

[[ "${1:-}" == --help || -z "${1:-}" ]] && usage
TARGET="$1"
THREADS="${THREADS:-$DEF_THREADS}"
RATE="${RATE:-$RATE_LIMIT}"

log(){ echo -e "\033[1;34m[*] $*\033[0m"; }
ok(){ echo -e "\033[1;32m[OK] $*\033[0m"; }
fail(){ echo -e "\033[1;31m[FAIL] $*\033[0m"; FAIL_COUNT=$((FAIL_COUNT+1)); }

FAIL_COUNT=0
run() {
  local DESC="$1"; shift
  log "$DESC"
  "$@" && ok "$DESC" || fail "$DESC"
}

######################################
# TOOL CHECK
######################################
NEEDED=(subfinder dnsx nuclei dalfox sqlmap ffuf)
missing=(); for t in "${NEEDED[@]}"; do command -v $t>/dev/null||missing+=($t);done
if (( ${#missing[@]} )); then
  fail "Missing tools: ${missing[*]}"
  read -rp "Continue anyway? (y/n) " ans
  [[ $ans =~ ^[Yy]$ ]] || exit 1
fi

export NUCLEI_RATELIMIT="$RATE"

time_start=$(date +%s)

######################################
# STAGE 1 – RECON
######################################
run "Recon script" "$RECON_SCRIPT" "$TARGET"

OUT_DIR=$(ls -td results_${TARGET}_* 2>/dev/null | head -n1 || true)
if [[ -z "$OUT_DIR" ]]; then
  fail "Recon output directory not found; skipping bug‑hunt."
  exit 1
fi

######################################
# ASK / AUTO CONTINUE
######################################
read -rp "Proceed to bug‑hunt? (y/n) " ans
[[ $ans =~ ^[Yy]$ ]] || { log "User skipped bug‑hunt."; exit 0; }

######################################
# STAGE 2 – BUG HUNT
######################################
run "Bug‑hunt automation" "$BUG_SCRIPT" "$OUT_DIR" "$THREADS"

######################################
# FINISH
######################################
elapsed=$(( $(date +%s) - time_start ))
log "Completed with $FAIL_COUNT failures. Total time $(printf '%02dh:%02dm:%02ds' $((elapsed/3600)) $((elapsed%3600/60)) $((elapsed%60)) )"
log "Results in $OUT_DIR"
