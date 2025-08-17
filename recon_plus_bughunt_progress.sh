#!/usr/bin/env bash
# recon_plus_bughunt_progress.sh
# Resilient Recon + BugHunt with:
#   • auto resource tuning
#   • wordlist/template sync
#   • per‑step % progress + ETA
#
# Usage: ./recon_plus_bughunt_progress.sh example.com
#
set -uo pipefail   # keep running even if a command fails

TARGET="${1:-}"
[[ -z "$TARGET" ]] && { echo "Usage: $0 <domain>"; exit 1; }

### Progress helpers --------------------------------------------------------
STEPS=(
  "Recon"
  "Nuclei_takeovers"
  "Subzy_takeovers"
  "Nuclei_exposures"
  "Nuclei_defaultlogins"
  "Dalfox_XSS"
  "SQLmap_SQLi"
  "SecretFinder_JS"
  "Trufflehog_JS"
  "Corsy_CORS"
  "FFUF_bruteforce"
  "Nuclei_serviceCVEs"
  "Nuclei_blindSSRF"
)
TOTAL_STEPS=${#STEPS[@]}
STEP_INDEX=0
START_TS=$(date +%s)

human() {                             # seconds -> H:MM:SS
  printf '%02dh:%02dm:%02ds' $(( $1/3600 )) $(( ($1%3600)/60 )) $(( $1%60 ))
}

show_progress() {
  local NOW=$(date +%s)
  local ELAPSED=$((NOW-START_TS))
  local PERC=$((STEP_INDEX*100/TOTAL_STEPS))
  local ETA=0
  if (( STEP_INDEX > 0 )); then
    ETA=$(( ELAPSED*(TOTAL_STEPS-STEP_INDEX)/STEP_INDEX ))
  fi
  echo -e "\033[1;35m[PROGRESS]\033[0m ${PERC}% | elapsed $(human $ELAPSED) | est. remaining $(human $ETA)"
}

### Logging wrappers --------------------------------------------------------
info(){ echo -e "\033[1;34m[*]\033[0m $*"; }
ok(){   echo -e "\033[1;32m[OK]\033[0m $*"; }
warn(){ echo -e "\033[1;33m[WARN]\033[0m $*"; }

run() {
  local DESC="$1"; shift
  info "$DESC"
  "$@" && ok "$DESC" || warn "$DESC failed (ignored)"
  STEP_INDEX=$((STEP_INDEX+1))
  show_progress
}

### Auto resource tuning ----------------------------------------------------
CORES=$( (nproc 2>/dev/null || sysctl -n hw.logicalcpu 2>/dev/null) || echo 2 )
RAM_GB=$(awk '/MemTotal/{printf "%.0f", $2/1024/1024}' /proc/meminfo 2>/dev/null || echo 4)

if [[ "$RAM_GB" -le 4 ]]; then
  THREADS_FFUF=50; SQLMAP_THREADS=2; DALFOX_WORKER=10
elif [[ "$RAM_GB" -le 8 ]]; then
  THREADS_FFUF=100; SQLMAP_THREADS=4; DALFOX_WORKER=20
else
  THREADS_FFUF=$((CORES*50)); SQLMAP_THREADS=6; DALFOX_WORKER=$((CORES*5))
fi
export NUCLEI_RATELIMIT=$((CORES*200))

### Wordlist / template sync -------------------------------------------------
WORD_HOME="$HOME/.wordlists"
LIST_PATH="$WORD_HOME/raft/raft-medium-directories.txt"
if [[ ! -f "$LIST_PATH" ]]; then
  info "Downloading raft wordlist..."
  mkdir -p "$(dirname "$LIST_PATH")"
  curl -Ls https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-medium-directories.txt -o "$LIST_PATH"         && ok "Wordlist ready" || warn "Wordlist download failed"
fi

command -v nuclei >/dev/null 2>&1 && run "Updating nuclei templates" nuclei -update-templates

### Recon phase --------------------------------------------------------------
if [[ -x ./recon_full.sh ]]; then
  run "Recon" ./recon_full.sh "$TARGET"
else
  warn "recon_full.sh not found – skipping recon"
  STEP_INDEX=$((STEP_INDEX+1)); show_progress
fi

OUTDIR=$(ls -td results_${TARGET}_* 2>/dev/null | head -n1)
if [[ -z "$OUTDIR" ]]; then
  warn "Recon output dir not found – creating empty OUTDIR"
  OUTDIR="results_${TARGET}_$(date +%s)"
  mkdir -p "$OUTDIR"
fi

BUGDIR="$OUTDIR/bug_results"; mkdir -p "$BUGDIR"

### BugHunt steps ------------------------------------------------------------

[[ -f "$OUTDIR/subdomains.txt" ]] && run "Nuclei takeovers" nuclei -silent -rl $NUCLEI_RATELIMIT -t takeovers/ -l "$OUTDIR/subdomains.txt" -o "$BUGDIR/takeovers_nuclei.txt"
command -v subzy >/dev/null && run "Subzy takeovers" subzy run --targets "$OUTDIR/subdomains.txt" --hide_fails -o "$BUGDIR/takeovers_subzy.txt"

[[ -f "$OUTDIR/resolved.txt" ]] && run "Nuclei exposures" nuclei -silent -rl $NUCLEI_RATELIMIT -t exposures/ -l "$OUTDIR/resolved.txt" -o "$BUGDIR/exposures.txt"
[[ -f "$OUTDIR/resolved.txt" ]] && run "Nuclei default-logins" nuclei -silent -rl $NUCLEI_RATELIMIT -t default-logins/ -l "$OUTDIR/resolved.txt" -o "$BUGDIR/default_logins.txt"

[[ -f "$OUTDIR/params_xss.txt" ]] && run "Dalfox XSS" dalfox file "$OUTDIR/params_xss.txt" --worker=$DALFOX_WORKER --skip-bav -o "$BUGDIR/dalfox_xss.txt"

[[ -f "$OUTDIR/params_sqli.txt" ]] && run "SQLmap SQLi" sqlmap -m "$OUTDIR/params_sqli.txt" --batch --risk=2 --level=2 --threads=$SQLMAP_THREADS --output-dir="$BUGDIR/sqlmap_out"

if [[ -f "$OUTDIR/js_files.txt" ]]; then
  run "SecretFinder JS" python3 $(which SecretFinder.py 2>/dev/null || echo SecretFinder.py) -i "$OUTDIR/js_files.txt" -o cli > "$BUGDIR/js_secrets.txt"
  while read -r jsurl; do
    run "Trufflehog JS $jsurl" bash -c "curl -s '$jsurl' | trufflehog stdin --regex --entropy=False --json >> '$BUGDIR/trufflehog.json'"
  done < "$OUTDIR/js_files.txt"
else
  STEP_INDEX=$((STEP_INDEX+2)); show_progress  # skip SecretFinder + trufflehog
fi

[[ -f "$OUTDIR/resolved.txt" ]] && run "Corsy" corsy -i "$OUTDIR/resolved.txt" -o "$BUGDIR/corsy_report"

if [[ -f "$OUTDIR/resolved.txt" ]]; then
  # treat ffuf whole loop as one step for progress
  run "FFUF brute-force" bash -c 'head -n 30 "'"$OUTDIR"'/resolved.txt" | while read -r host; do ffuf -mc all -t "'"$THREADS_FFUF"'" -w "'"$LIST_PATH"'" -u "https://${host}/FUZZ" -o "'"$BUGDIR"'/ffuf_${host//[^a-zA-Z0-9]/_}.json" 2>/dev/null; done'
fi

if [[ -f "$OUTDIR/ports.txt" ]]; then
  awk '{print "http://"$1":"$2}' "$OUTDIR/ports.txt" > "$BUGDIR/hostports.txt"
  run "Nuclei service CVEs" nuclei -silent -rl $NUCLEI_RATELIMIT -t cves/ -l "$BUGDIR/hostports.txt" -o "$BUGDIR/service_cves.txt"
else
  STEP_INDEX=$((STEP_INDEX+1)); show_progress
fi

if command -v interactsh-client >/dev/null 2>&1 && [[ -f "$OUTDIR/params_ssrf.txt" ]]; then
  run "Interactsh client" interactsh-client -q -o "$BUGDIR/int.url"
  IURL=$(cat "$BUGDIR/int.url" 2>/dev/null || echo "")
  [[ -n "$IURL" ]] && run "Nuclei blind SSRF" nuclei -silent -rl $NUCLEI_RATELIMIT -t vulnerabilities/ -l "$OUTDIR/params_ssrf.txt" -interactsh-url "$IURL" -o "$BUGDIR/ssrf_blind.txt"
else
  STEP_INDEX=$((STEP_INDEX+1)); show_progress
fi

ok "Script finished. Outputs in $BUGDIR"
