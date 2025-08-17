#!/usr/bin/env bash
# recon_plus_bughunt_auto.sh
# One‑shot Recon + BugHunt with:
#   • auto‑template / wordlist sync
#   • auto thread/rate sizing from CPU & RAM
#   • sequential full bughunt
#
# Usage: ./recon_plus_bughunt_auto.sh example.com
#
# Dependencies: subfinder, assetfinder, dnsx, naabu, httpx, waybackurls, gau, gauplus, gf,
#               nuclei, dalfox, sqlmap, ffuf, SecretFinder.py, trufflehog, corsy,
#               interactsh-client (optional), subzy (optional), curl, awk
#
set -euo pipefail

TARGET="${1:-}"
[[ -z "$TARGET" ]] && { echo "Usage: $0 <domain>"; exit 1; }

##### Detect system resources #################################################
CORES=$( (nproc 2>/dev/null || sysctl -n hw.logicalcpu 2>/dev/null) || echo 2 )
RAM_GB=$(awk '/MemTotal/{printf "%.0f", $2/1024/1024}' /proc/meminfo 2>/dev/null || echo 4)

# Thread sizing heuristics
if [[ "$RAM_GB" -le 4 ]]; then
  THREADS_FFUF=50
  SQLMAP_THREADS=2
  DALFOX_WORKER=10
elif [[ "$RAM_GB" -le 8 ]]; then
  THREADS_FFUF=100
  SQLMAP_THREADS=4
  DALFOX_WORKER=20
else
  THREADS_FFUF=$((CORES * 50))
  SQLMAP_THREADS=6
  DALFOX_WORKER=$((CORES * 5))
fi

export NUCLEI_RATELIMIT=$((CORES * 200))

##### Helper functions ########################################################
log()   { echo -e "\033[1;34m[*]\033[0m $*"; }
ok()    { echo -e "\033[1;32m[OK]\033[0m $*"; }
warn()  { echo -e "\033[1;33m[WARN]\033[0m $*"; }

##### Ensure wordlists / templates ###########################################
WORD_HOME="$HOME/.wordlists"
mkdir -p "$WORD_HOME"

LIST_DIR="$WORD_HOME/raft"
LIST_URL="https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-medium-directories.txt"
LIST_PATH="$LIST_DIR/raft-medium-directories.txt"

if [[ ! -f "$LIST_PATH" ]]; then
  log "Downloading ffuf wordlist..."
  mkdir -p "$LIST_DIR"
  curl -Ls "$LIST_URL" -o "$LIST_PATH" && ok "Wordlist saved -> $LIST_PATH" || warn "Download failed, ffuf may error"
fi

if command -v nuclei >/dev/null 2>&1; then
  log "Updating nuclei templates..."
  nuclei -update-templates
fi

##### Run Recon ###############################################################
if [[ ! -x ./recon_full.sh ]]; then
  warn "recon_full.sh not found or not executable in current directory!"
  exit 1
fi

./recon_full.sh "$TARGET"

OUTDIR=$(ls -td results_${TARGET}_* | head -n1)
[[ -d "$OUTDIR" ]] || { warn "Recon output directory not found"; exit 1; }

BUGDIR="$OUTDIR/bug_results"
mkdir -p "$BUGDIR"

##### Bug Hunt: Sequential full scan ##########################################
log "[BugHunt] Subdomain takeover..."
[[ -f "$OUTDIR/subdomains.txt" ]] && nuclei -silent -rl $NUCLEI_RATELIMIT -t takeovers/ -l "$OUTDIR/subdomains.txt" -o "$BUGDIR/takeovers_nuclei.txt" || true
command -v subzy >/dev/null && subzy run --targets "$OUTDIR/subdomains.txt" --hide_fails > "$BUGDIR/takeovers_subzy.txt" || true

log "[BugHunt] Exposure & default creds..."
[[ -f "$OUTDIR/resolved.txt" ]] && {
  nuclei -silent -rl $NUCLEI_RATELIMIT -t exposures/ -l "$OUTDIR/resolved.txt" -o "$BUGDIR/exposures.txt"
  nuclei -silent -rl $NUCLEI_RATELIMIT -t default-logins/ -l "$OUTDIR/resolved.txt" -o "$BUGDIR/default_logins.txt"
}

log "[BugHunt] XSS fuzz (Dalfox worker=$DALFOX_WORKER)..."
[[ -f "$OUTDIR/params_xss.txt" ]] && dalfox file "$OUTDIR/params_xss.txt" --worker=$DALFOX_WORKER --skip-bav -o "$BUGDIR/dalfox_xss.txt" || true

log "[BugHunt] SQLi scan (threads=$SQLMAP_THREADS)..."
[[ -f "$OUTDIR/params_sqli.txt" ]] && sqlmap -m "$OUTDIR/params_sqli.txt" --batch --risk=2 --level=2 --threads=$SQLMAP_THREADS --output-dir="$BUGDIR/sqlmap_out" || true

log "[BugHunt] JS secrets (SecretFinder + trufflehog)..."
if [[ -f "$OUTDIR/js_files.txt" ]]; then
  python3 $(which SecretFinder.py 2>/dev/null || echo SecretFinder.py) -i "$OUTDIR/js_files.txt" -o cli > "$BUGDIR/js_secrets.txt" 2>/dev/null || true
  while read -r jsurl; do
    curl -s "$jsurl" | trufflehog stdin --regex --entropy=False --json >> "$BUGDIR/trufflehog.json" || true
  done < "$OUTDIR/js_files.txt"
fi

log "[BugHunt] CORS misconfig (corsy)..."
[[ -f "$OUTDIR/resolved.txt" ]] && corsy -i "$OUTDIR/resolved.txt" -o "$BUGDIR/corsy_report" >/dev/null 2>&1 || true

log "[BugHunt] Directory brute-force (ffuf threads=$THREADS_FFUF)..."
if [[ -f "$OUTDIR/resolved.txt" ]]; then
  head -n 30 "$OUTDIR/resolved.txt" | while read -r host; do
    ffuf -mc all -t "$THREADS_FFUF" -w "$LIST_PATH" -u "https://${host}/FUZZ" -o "$BUGDIR/ffuf_${host//[^a-zA-Z0-9]/_}.json" 2>/dev/null || true
  done
fi

log "[BugHunt] Service CVE scan..."
if [[ -f "$OUTDIR/ports.txt" ]]; then
  awk '{print "http://"$1":"$2}' "$OUTDIR/ports.txt" > "$BUGDIR/hostports.txt"
  nuclei -silent -rl $NUCLEI_RATELIMIT -t cves/ -l "$BUGDIR/hostports.txt" -o "$BUGDIR/service_cves.txt" || true
fi

log "[BugHunt] Blind SSRF/XSS (Interactsh)..."
if command -v interactsh-client >/dev/null 2>&1 && [[ -f "$OUTDIR/params_ssrf.txt" ]]; then
  interactsh-client -q -o "$BUGDIR/int.url"
  IURL=$(cat "$BUGDIR/int.url")
  nuclei -silent -rl $NUCLEI_RATELIMIT -t vulnerabilities/ -l "$OUTDIR/params_ssrf.txt" -interactsh-url "$IURL" -o "$BUGDIR/ssrf_blind.txt" || true
fi

log "[✓] Recon + BugHunt complete. All results: $BUGDIR"
