#!/usr/bin/env bash
# recon_plus_bughunt_extended.sh
# Ultimate Resilient Recon + BugHunt with progress bar, auto‑resources,
# Katana (crawler) + Feroxbuster (fast dir brute) integrated.
#
# Usage: ./recon_plus_bughunt_extended.sh example.com
#
# Dependencies:
#   subfinder assetfinder dnsx naabu httpx waybackurls gau gauplus gf
#   nuclei dalfox sqlmap ffuf feroxbuster katana
#   SecretFinder.py trufflehog corsy interactsh-client (opt) subzy (opt)
#
set -uo pipefail

TARGET="${1:-}"
[[ -z "$TARGET" ]] && { echo "Usage: $0 <domain>"; exit 1; }

### Progress array ----------------------------------------------------------
STEPS=(
  "Recon"
  "Katana_crawl"
  "Nuclei_takeovers"
  "Subzy_takeovers"
  "Nuclei_exposures"
  "Nuclei_defaultlogins"
  "Dalfox_XSS"
  "SQLmap_SQLi"
  "Feroxbuster_bruteforce"
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

human() { printf '%02dh:%02dm:%02ds' $(( $1/3600 )) $(( ($1%3600)/60 )) $(( $1%60 )); }

show_progress() {
  local NOW=$(date +%s)
  local ELAPSED=$((NOW-START_TS))
  local PERC=$((STEP_INDEX*100/TOTAL_STEPS))
  local ETA=0
  (( STEP_INDEX > 0 )) && ETA=$(( ELAPSED*(TOTAL_STEPS-STEP_INDEX)/STEP_INDEX ))
  echo -e "\033[1;35m[PROGRESS]\033[0m ${PERC}% | elapsed $(human $ELAPSED) | est. remaining $(human $ETA)"
}

### Logging helpers ---------------------------------------------------------
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
  THREADS_FFUF=50; SQLMAP_THREADS=2; DALFOX_WORKER=10; FEROX_THREADS=20
elif [[ "$RAM_GB" -le 8 ]]; then
  THREADS_FFUF=100; SQLMAP_THREADS=4; DALFOX_WORKER=20; FEROX_THREADS=50
else
  THREADS_FFUF=$((CORES*50)); SQLMAP_THREADS=6; DALFOX_WORKER=$((CORES*5)); FEROX_THREADS=$((CORES*100))
fi
export NUCLEI_RATELIMIT=$((CORES*200))

### Wordlist / template sync -------------------------------------------------
WORD_HOME="$HOME/.wordlists"
LIST_MED="$WORD_HOME/raft/raft-medium-directories.txt"
LIST_LARGE="$WORD_HOME/raft/raft-large-directories.txt"
mkdir -p "$(dirname "$LIST_MED")"
[[ ! -f "$LIST_MED" ]] && {
  info "Downloading raft-medium wordlist..."
  curl -Ls https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-medium-directories.txt -o "$LIST_MED"         && ok "raft-medium ready" || warn "Failed raft-medium"
}
[[ ! -f "$LIST_LARGE" ]] && {
  info "Downloading raft-large wordlist..."
  curl -Ls https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-large-directories.txt -o "$LIST_LARGE"         && ok "raft-large ready" || warn "Failed raft-large"
}

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

### Katana crawl -------------------------------------------------------------
if command -v katana >/dev/null 2>&1 && [[ -f "$OUTDIR/resolved.txt" ]]; then
  run "Katana crawl" katana -silent -list "$OUTDIR/resolved.txt" -jc -o "$OUTDIR/urls_katana.txt"
  if [[ -f "$OUTDIR/urls_katana.txt" ]]; then
    cat "$OUTDIR/urls_katana.txt" "$OUTDIR/urls.txt" 2>/dev/null | sort -u > "$OUTDIR/urls.tmp"
    mv "$OUTDIR/urls.tmp" "$OUTDIR/urls.txt"
  fi
else
  STEP_INDEX=$((STEP_INDEX+1)); show_progress
fi

### BugHunt steps ------------------------------------------------------------

[[ -f "$OUTDIR/subdomains.txt" ]] && run "Nuclei takeovers" nuclei -silent -rl $NUCLEI_RATELIMIT -t takeovers/ -l "$OUTDIR/subdomains.txt" -o "$BUGDIR/takeovers_nuclei.txt"
command -v subzy >/dev/null && run "Subzy takeovers" subzy run --targets "$OUTDIR/subdomains.txt" --hide_fails -o "$BUGDIR/takeovers_subzy.txt"

[[ -f "$OUTDIR/resolved.txt" ]] && run "Nuclei exposures" nuclei -silent -rl $NUCLEI_RATELIMIT -t exposures/ -l "$OUTDIR/resolved.txt" -o "$BUGDIR/exposures.txt"
[[ -f "$OUTDIR/resolved.txt" ]] && run "Nuclei default-logins" nuclei -silent -rl $NUCLEI_RATELIMIT -t default-logins/ -l "$OUTDIR/resolved.txt" -o "$BUGDIR/default_logins.txt"

[[ -f "$OUTDIR/params_xss.txt" ]] && run "Dalfox XSS" dalfox file "$OUTDIR/params_xss.txt" --worker=$DALFOX_WORKER --skip-bav -o "$BUGDIR/dalfox_xss.txt"

[[ -f "$OUTDIR/params_sqli.txt" ]] && run "SQLmap SQLi" sqlmap -m "$OUTDIR/params_sqli.txt" --batch --risk=2 --level=2 --threads=$SQLMAP_THREADS --output-dir="$BUGDIR/sqlmap_out"

### Feroxbuster brute --------------------------------------------------------
if command -v feroxbuster >/dev/null 2>&1 && [[ -f "$OUTDIR/resolved.txt" ]]; then
  run "Feroxbuster brute" bash -c 'head -n 20 "'"$OUTDIR"'/resolved.txt" | xargs -I{} -P5 feroxbuster -q -t '"$FEROX_THREADS"' -u https://{} -w '"$LIST_LARGE"' -o "'"$BUGDIR"'/ferox_{}.txt"'
else
  STEP_INDEX=$((STEP_INDEX+1)); show_progress
fi

### JS Secrets ---------------------------------------------------------------
if [[ -f "$OUTDIR/js_files.txt" ]]; then
  run "SecretFinder JS" python3 $(which SecretFinder.py 2>/dev/null || echo SecretFinder.py) -i "$OUTDIR/js_files.txt" -o cli > "$BUGDIR/js_secrets.txt"
  while read -r jsurl; do
    run "Trufflehog JS $jsurl" bash -c "curl -s '$jsurl' | trufflehog stdin --regex --entropy=False --json >> '$BUGDIR/trufflehog.json'"
  done < "$OUTDIR/js_files.txt"
else
  STEP_INDEX=$((STEP_INDEX+2)); show_progress  # skip both SecretFinder & trufflehog
fi

[[ -f "$OUTDIR/resolved.txt" ]] && run "Corsy" corsy -i "$OUTDIR/resolved.txt" -o "$BUGDIR/corsy_report"

### ffuf brute (medium list) -------------------------------------------------
if [[ -f "$OUTDIR/resolved.txt" ]]; then
  run "FFUF brute-force" bash -c 'head -n 30 "'"$OUTDIR"'/resolved.txt" | while read -r h; do ffuf -mc all -t '"$THREADS_FFUF"' -w "'"$LIST_MED"'" -u "https://${h}/FUZZ" -o "'"$BUGDIR"'/ffuf_${h//[^a-zA-Z0-9]/_}.json" 2>/dev/null; done'
else
  STEP_INDEX=$((STEP_INDEX+1)); show_progress
fi

### Service CVE scan ---------------------------------------------------------
if [[ -f "$OUTDIR/ports.txt" ]]; then
  awk '{print "http://"$1":"$2}' "$OUTDIR/ports.txt" > "$BUGDIR/hostports.txt"
  run "Nuclei service CVEs" nuclei -silent -rl $NUCLEI_RATELIMIT -t cves/ -l "$BUGDIR/hostports.txt" -o "$BUGDIR/service_cves.txt"
else
  STEP_INDEX=$((STEP_INDEX+1)); show_progress
fi

### Blind SSRF/XSS -----------------------------------------------------------
if command -v interactsh-client >/dev/null 2>&1 && [[ -f "$OUTDIR/params_ssrf.txt" ]]; then
  run "Interactsh client" interactsh-client -q -o "$BUGDIR/int.url"
  IURL=$(cat "$BUGDIR/int.url" 2>/dev/null || echo "")
  [[ -n "$IURL" ]] && run "Nuclei blind SSRF" nuclei -silent -rl $NUCLEI_RATELIMIT -t vulnerabilities/ -l "$OUTDIR/params_ssrf.txt" -interactsh-url "$IURL" -o "$BUGDIR/ssrf_blind.txt"
else
  STEP_INDEX=$((STEP_INDEX+1)); show_progress
fi

ok "All tasks finished. Check $BUGDIR"
