#!/usr/bin/env bash
# recon_plus_bughunt_resilient.sh
# Recon + BugHunt with auto resources, template sync, *and* graceful error‑handling
#
# Any step fails → শুধু ছোট্ট ওয়ার্নিং; স্ক্রিপ্ট থামবে না
#
# Usage: ./recon_plus_bughunt_resilient.sh example.com
#
set -uo pipefail   # -e বাদ, যাতে কমান্ড ফেইল হলেও বের না হয়

TARGET="${1:-}"
[[ -z "$TARGET" ]] && { echo "Usage: $0 <domain>"; exit 1; }

#### Logging helpers ####
info(){ echo -e "\033[1;34m[*]\033[0m $*"; }
ok(){   echo -e "\033[1;32m[OK]\033[0m $*"; }
warn(){ echo -e "\033[1;33m[WARN]\033[0m $*"; }

# Wrapper that never exits script
run() {
  CMD_DESC="$1"; shift
  info "$CMD_DESC"
  "$@" && ok "$CMD_DESC" || warn "$CMD_DESC failed (ignored)"
}

#### Auto resource detect ####
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

#### Wordlist + templates sync ####
WORD_HOME="$HOME/.wordlists"
LIST_PATH="$WORD_HOME/raft/raft-medium-directories.txt"
[[ ! -f "$LIST_PATH" ]] && {
  info "Downloading raft wordlist..."
  mkdir -p "$(dirname "$LIST_PATH")"
  curl -Ls https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-medium-directories.txt -o "$LIST_PATH"         && ok "Wordlist ready" || warn "Wordlist download failed"
}

command -v nuclei >/dev/null 2>&1 && run "Updating nuclei templates" nuclei -update-templates

#### Recon phase ####
if [[ -x ./recon_full.sh ]]; then
  run "Running recon_full.sh" ./recon_full.sh "$TARGET"
else
  warn "recon_full.sh not found – skipping recon"
fi

OUTDIR=$(ls -td results_${TARGET}_* 2>/dev/null | head -n1)
if [[ -z "$OUTDIR" ]]; then
  warn "Recon output dir not found – creating empty OUTDIR"
  OUTDIR="results_${TARGET}_$(date +%s)"
  mkdir -p "$OUTDIR"
fi

BUGDIR="$OUTDIR/bug_results"; mkdir -p "$BUGDIR"

#### BugHunt scans (each with run wrapper) ####
[[ -f "$OUTDIR/subdomains.txt" ]] && run "Nuclei takeovers" nuclei -silent -rl $NUCLEI_RATELIMIT -t takeovers/ -l "$OUTDIR/subdomains.txt" -o "$BUGDIR/takeovers_nuclei.txt"
command -v subzy >/dev/null && run "Subzy takeover" subzy run --targets "$OUTDIR/subdomains.txt" --hide_fails -o "$BUGDIR/takeovers_subzy.txt"

[[ -f "$OUTDIR/resolved.txt" ]] && {
  run "Nuclei exposures" nuclei -silent -rl $NUCLEI_RATELIMIT -t exposures/ -l "$OUTDIR/resolved.txt" -o "$BUGDIR/exposures.txt"
  run "Nuclei default-logins" nuclei -silent -rl $NUCLEI_RATELIMIT -t default-logins/ -l "$OUTDIR/resolved.txt" -o "$BUGDIR/default_logins.txt"
}

[[ -f "$OUTDIR/params_xss.txt" ]] && run "Dalfox XSS" dalfox file "$OUTDIR/params_xss.txt" --worker=$DALFOX_WORKER --skip-bav -o "$BUGDIR/dalfox_xss.txt"

[[ -f "$OUTDIR/params_sqli.txt" ]] && run "SQLmap SQLi" sqlmap -m "$OUTDIR/params_sqli.txt" --batch --risk=2 --level=2 --threads=$SQLMAP_THREADS --output-dir="$BUGDIR/sqlmap_out"

if [[ -f "$OUTDIR/js_files.txt" ]]; then
  run "SecretFinder" python3 $(which SecretFinder.py 2>/dev/null || echo SecretFinder.py) -i "$OUTDIR/js_files.txt" -o cli > "$BUGDIR/js_secrets.txt"
  while read -r jsurl; do
    run "trufflehog on $jsurl" bash -c "curl -s '$jsurl' | trufflehog stdin --regex --entropy=False --json >> '$BUGDIR/trufflehog.json'"
  done < "$OUTDIR/js_files.txt"
fi

[[ -f "$OUTDIR/resolved.txt" ]] && run "Corsy" corsy -i "$OUTDIR/resolved.txt" -o "$BUGDIR/corsy_report"

if [[ -f "$OUTDIR/resolved.txt" ]]; then
  head -n 30 "$OUTDIR/resolved.txt" | while read -r host; do
    run "ffuf on $host" ffuf -mc all -t "$THREADS_FFUF" -w "$LIST_PATH" -u "https://${host}/FUZZ" -o "$BUGDIR/ffuf_${host//[^a-zA-Z0-9]/_}.json"
  done
fi

if [[ -f "$OUTDIR/ports.txt" ]]; then
  awk '{print "http://"$1":"$2}' "$OUTDIR/ports.txt" > "$BUGDIR/hostports.txt"
  run "Nuclei service CVEs" nuclei -silent -rl $NUCLEI_RATELIMIT -t cves/ -l "$BUGDIR/hostports.txt" -o "$BUGDIR/service_cves.txt"
fi

if command -v interactsh-client >/dev/null 2>&1 && [[ -f "$OUTDIR/params_ssrf.txt" ]]; then
  run "Interactsh registration" interactsh-client -q -o "$BUGDIR/int.url"
  IURL=$(cat "$BUGDIR/int.url" 2>/dev/null || echo "")
  [[ -n "$IURL" ]] && run "Nuclei blind SSRF/XSS" nuclei -silent -rl $NUCLEI_RATELIMIT -t vulnerabilities/ -l "$OUTDIR/params_ssrf.txt" -interactsh-url "$IURL" -o "$BUGDIR/ssrf_blind.txt"
fi

ok "All tasks attempted – check $BUGDIR for outputs (some may be empty if step failed)"
