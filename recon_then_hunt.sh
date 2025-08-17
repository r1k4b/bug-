#!/usr/bin/env bash
# recon_then_hunt.sh
# One‑shot: Recon + Bug Hunt
# Usage: ./recon_then_hunt.sh example.com [threads]
#
# Steps:
#   1. Runs recon_full.sh <domain>
#   2. When recon finishes, passes its output dir to bughunt_auto.sh
#   3. Final bug results saved under same recon folder.
#
# Prerequisites: recon_full.sh, bughunt_auto.sh in PATH or same folder;
#   plus all tools those scripts need.

set -euo pipefail

domain="$1"
THREADS="${2:-100}"

if [[ -z "$domain" ]]; then
  echo "Usage: $0 example.com [threads]"
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

RECON_SCRIPT="${SCRIPT_DIR}/recon_full.sh"
BUG_SCRIPT="${SCRIPT_DIR}/bughunt_auto.sh"

if [[ ! -x "$RECON_SCRIPT" || ! -x "$BUG_SCRIPT" ]]; then
  echo "Missing recon_full.sh or bughunt_auto.sh executable in $SCRIPT_DIR"
  exit 1
fi

echo "=== [Stage 1] Recon ==="
"$RECON_SCRIPT" "$domain"

# find latest results dir for domain
latest_out=$(ls -td results_${domain}_* | head -n1)
if [[ ! -d "$latest_out" ]]; then
  echo "Recon output dir not found!"
  exit 1
fi

echo "=== [Stage 2] Bug Hunt ==="
"$BUG_SCRIPT" "$latest_out" "$THREADS"

echo "=== All Done! ==="
echo "Combined output under: $latest_out"
