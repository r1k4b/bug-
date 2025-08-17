#!/usr/bin/env bash
# bughunt_auto_parallel.sh
# Bug-hunt with hybrid parallel logic (safe + fast)
#
# Usage:
#   ./bughunt_auto_parallel.sh <recon_dir> [--parallel]
#
# If --parallel flag given, run light tools parallel, heavy sequential.

set -uo pipefail

OUTDIR="${1:-}"
PARALLEL="${2:-}"

[[ -z "$OUTDIR" || ! -d "$OUTDIR" ]] && { echo "Usage: $0 <recon_dir> [--parallel]"; exit 1; }

BUGDIR="${OUTDIR}/bug_results"
mkdir -p "$BUGDIR"

run_bg() { echo "[BG] $*"; "$@" & PIDS+=($!); }
run_fg() { echo "[FG] $*"; "$@"; }

# === Parallel-friendly tools ===
run_parallel_tools() {
  run_bg nuclei -silent -t takeovers/ -l "$OUTDIR/subdomains.txt" -o "$BUGDIR/takeovers.txt"
  run_bg nuclei -silent -t exposures/ -l "$OUTDIR/resolved.txt" -o "$BUGDIR/exposures.txt"
  run_bg dalfox file "$OUTDIR/params_xss.txt" --skip-bav --silence -o "$BUGDIR/dalfox_xss.txt"
  run_bg python3 SecretFinder.py -i "$OUTDIR/js_files.txt" -o cli > "$BUGDIR/js_secrets.txt"

  wait  # Wait for parallel group finish
}

# === Heavy sequential tools ===
run_heavy_tools() {
  run_fg sqlmap -m "$OUTDIR/params_sqli.txt" --batch --smart --threads=4 --output-dir="$BUGDIR/sqlmap_out"

  # ffuf limited hosts
  head -n 30 "$OUTDIR/resolved.txt" | while read -r host; do
    run_fg ffuf -mc all -t 50 -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
      -u "https://${host}/FUZZ" -o "$BUGDIR/ffuf_${host//[^a-zA-Z0-9]/_}.json"
  done

  run_fg corsy -i "$OUTDIR/resolved.txt" -o "$BUGDIR/corsy_report"
}

# === Execution logic ===
if [[ "$PARALLEL" == "--parallel" ]]; then
  echo "[*] Running in HYBRID-PARALLEL mode."
  run_parallel_tools
else
  echo "[*] Running SEQUENTIAL mode."
  nuclei -silent -t takeovers/ -l "$OUTDIR/subdomains.txt" -o "$BUGDIR/takeovers.txt"
  nuclei -silent -t exposures/ -l "$OUTDIR/resolved.txt" -o "$BUGDIR/exposures.txt"
  dalfox file "$OUTDIR/params_xss.txt" --skip-bav --silence -o "$BUGDIR/dalfox_xss.txt"
  python3 SecretFinder.py -i "$OUTDIR/js_files.txt" -o cli > "$BUGDIR/js_secrets.txt"
fi

run_heavy_tools

echo "[✓] Bug-hunt complete. Results in $BUGDIR"
