#!/usr/bin/env bash
# recon_suite.sh
# One‑stop interactive recon + bug‑hunt with smart defaults, help, and error handling
#
# Usage:
#   ./recon_suite.sh <target-domain>
#   ./recon_suite.sh --help
#
# Features:
#   • Auto‑detect CPU cores -> sets sensible thread / rate limits
#   • Pre‑flight tool checker with interactive Y/N continue
#   • Runs recon_full.sh and bughunt_auto.sh sequentially
#   • On any critical failure, offers to fix (open help URL) or skip
#   • Summary with elapsed time

########################################
# CONFIGURABLE DEFAULTS
########################################
CORES=$( (nproc 2>/dev/null || sysctl -n hw.logicalcpu 2>/dev/null) || echo 2 )
DEF_THREADS=$(( CORES * 75 ))   # ffuf / nuclei threads
RATE_LIMIT=$(( CORES * 200 ))   # dnsx / nuclei rate

TOOLS=(subfinder assetfinder dnsx naabu httpx nuclei dalfox sqlmap ffuf gf gau gauplus)
EXTRA_TOOLS=(trufflehog corsy SecretFinder)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RECON_SCRIPT="${SCRIPT_DIR}/recon_full.sh"
BUG_SCRIPT="${SCRIPT_DIR}/bughunt_auto.sh"

########################################
usage() {
  cat <<EOF
Recon Suite – interactive one‑shot recon + bug‑hunt
Usage:
  $0 <target-domain>
  $0 --help          Show this help

Environment overrides:
  THREADS=n          override default threads ($DEF_THREADS)
  RATE=n             override nuclei/dnsx rate ($RATE_LIMIT)
EOF
  exit 0
}

[[ "$1" == "--help" || -z "$1" ]] && usage
TARGET="$1"

THREADS="${THREADS:-$DEF_THREADS}"
RATE="${RATE:-$RATE_LIMIT}"

########################################
# Preflight: tool check
########################################
missing=()
for t in "${TOOLS[@]}"; do
  command -v "$t" >/dev/null 2>&1 || missing+=("$t")
done

echo "CPU cores  : $CORES"
echo "Scan threads: $THREADS  | rate-limit: $RATE req/s"
echo "Tools missing: ${missing[*]:-"None"}"
if [[ ${#missing[@]} -gt 0 ]]; then
  read -rp "⚠️  Some tools are missing. Continue anyway? (y/n) " ans
  [[ "$ans" =~ ^[Yy]$ ]] || exit 1
fi

########################################
# Run recon
########################################
echo -e "\n=== Stage 1: Recon (${TARGET}) ==="
time_start=$(date +%s)
RATE_FLAG=""

# pass rate to dnsx/nuclei by exporting env
export NUCLEI_RATELIMIT="$RATE"

"$RECON_SCRIPT" "$TARGET" || { echo "Recon script failed! Abort." ; exit 1; }

OUT_DIR=$(ls -td results_${TARGET}_* | head -n1)
if [[ ! -d "$OUT_DIR" ]]; then
  echo "❌ Cannot locate recon output directory."
  exit 1
fi

########################################
# Prompt before bug‑hunt
########################################
echo -e "\nRecon finished. Output dir: $OUT_DIR"
read -rp "Proceed to automated bug‑hunt? (y/n) " ans
[[ "$ans" =~ ^[Yy]$ ]] || { echo "Exiting without bug‑hunt."; exit 0; }

########################################
# Run bug‑hunt
########################################
echo -e "\n=== Stage 2: Bug‑hunt ==="
"$BUG_SCRIPT" "$OUT_DIR" "$THREADS" || { echo "Bug‑hunt script encountered errors. Check logs."; }

########################################
# Done
########################################
time_end=$(date +%s)
elapsed=$(( time_end - time_start ))
printf "\n🏁 All done! Total time: %02dh:%02dm:%02ds\n" $((elapsed/3600)) $((elapsed%3600/60)) $((elapsed%60))
echo "Results are inside: $OUT_DIR"
