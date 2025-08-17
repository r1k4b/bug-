#!/usr/bin/env bash
# one_sh_bughunt_pro.sh
# Single‑file, Pro‑level Recon + BugHunt pipeline
# Includes: Katana, Feroxbuster, httpx tech, ParamSpider, nmap vuln‑scripts, testssl, progress bar, auto resources
#
# Usage: ./one_sh_bughunt_pro.sh example.com
#
# Optional:
#   export WEBHOOK_URL="https://hooks.slack.com/services/XXX" (for completion ping)
#
# Dependencies:
#   subfinder assetfinder dnsx naabu httpx waybackurls gau gauplus gf paramspider
#   katana feroxbuster nuclei dalfox sqlmap ffuf nmap testssl.sh
#   SecretFinder.py trufflehog corsy interactsh-client (opt) subzy (opt)
#
set -uo pipefail

TARGET="${1:-}"
[[ -z "$TARGET" ]] && { echo "Usage: $0 <domain>"; exit 1; }

### Progress setup -----------------------------------------------------------
STEPS=(
  "Subdomain_enum"
  "Live_host_resolve"
  "HTTPX_tech_detect"
  "Port_scan_naabu"
  "Nmap_vuln_scan"
  "URL_harvest_params"
  "ParamSpider"
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
  "TestSSL"
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
  echo -e "\033[1;35m[PROGRESS]\033[0m ${PERC}% | elapsed $(human $ELAPSED) | est left $(human $ETA)"
}
info(){ echo -e "\033[1;34m[*]\033[0m $*"; }
ok(){   echo -e "\033[1;32m[OK]\033[0m $*"; }
warn(){ echo -e "\033[1;33m[WARN]\033[0m $*"; }

run() { local D="$1"; shift; info "$D"; "$@" && ok "$D" || warn "$D failed"; STEP_INDEX=$((STEP_INDEX+1)); show_progress; }

### Auto resources -----------------------------------------------------------
CORES=$( (nproc 2>/dev/null || sysctl -n hw.logicalcpu 2>/dev/null) || echo 2 )
RAM=$(awk '/MemTotal/{printf "%.0f",$2/1024/1024}' /proc/meminfo 2>/dev/null || echo 4)
if (( RAM<=4 )); then TH_FFUF=50; SQL_T=2; DLW=10; FEROX_T=20
elif (( RAM<=8 )); then TH_FFUF=100; SQL_T=4; DLW=20; FEROX_T=50
else TH_FFUF=$((CORES*50)); SQL_T=6; DLW=$((CORES*5)); FEROX_T=$((CORES*100)); fi
export NUCLEI_RATELIMIT=$((CORES*200))

### Wordlists / templates sync ----------------------------------------------
WL="$HOME/.wordlists"; mkdir -p "$WL/raft"
med="$WL/raft/raft-medium-directories.txt"; large="$WL/raft/raft-large-directories.txt"
[[ ! -f "$med" ]] && curl -Ls https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-medium-directories.txt -o "$med"
[[ ! -f "$large" ]] && curl -Ls https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-large-directories.txt -o "$large"
command -v nuclei >/dev/null 2>&1 && run "Update nuclei templates" nuclei -update-templates

### Output dirs --------------------------------------------------------------
TS=$(date +%Y%m%d_%H%M%S)
OUT="results_${TARGET}_${TS}"; mkdir -p "$OUT"
BUG="$OUT/bug_results"; mkdir -p "$BUG"
info "Output dir: $OUT"

### Recon steps --------------------------------------------------------------
run "Subdomain enum" bash -c 'subfinder -silent -d "'"$TARGET"'" -o "'"$OUT"'/sub1.txt"; assetfinder --subs-only "'"$TARGET"'" > "'"$OUT"'/sub2.txt" 2>/dev/null; cat "'"$OUT"'/sub*.txt" | sort -u > "'"$OUT"'/subdomains.txt"'

run "Live host resolve" dnsx -silent -l "$OUT/subdomains.txt" -o "$OUT/resolved.txt"

run "HTTPX tech detect" httpx -silent -l "$OUT/resolved.txt" -tech-detect -status-code -title -tls -o "$OUT/httpx.txt"

run "Port scan naabu" bash -c 'naabu -silent -p - -l "'"$OUT"'/resolved.txt" -o "'"$OUT"'/ports.txt" || true'

# Nmap vuln
if command -v nmap >/dev/null 2>&1; then
  run "Nmap vuln scan" bash -c 'while read -r ip port; do nmap -Pn -sV --script vuln -p $port $ip -oN "'"$OUT"'/nmap_${ip}_${port}.txt"; done < <(awk -F: "{print $1" "$2}" '"$OUT"'/ports.txt")'
else STEP_INDEX=$((STEP_INDEX+1)); show_progress; fi

# URL & Params
run "URL harvest & params" bash -c '
  cat "'"$OUT"'/resolved.txt" | waybackurls > "'"$OUT"'/urls1.txt";
  cat "'"$OUT"'/resolved.txt" | gau --subs > "'"$OUT"'/urls2.txt";
  first=$(head -n1 "'"$OUT"'/resolved.txt"); [[ -n "$first" ]] && gauplus -subs -o "'"$OUT"'/urls3.txt" "$first" >/dev/null 2>&1 || true;
  cat "'"$OUT"'/urls*.txt" | sort -u > "'"$OUT"'/urls.txt";
  cat "'"$OUT"'/urls.txt" | gf xss > "'"$OUT"'/params_xss.txt";
  cat "'"$OUT"'/urls.txt" | gf sqli > "'"$OUT"'/params_sqli.txt";
  cat "'"$OUT"'/urls.txt" | gf ssrf > "'"$OUT"'/params_ssrf.txt";
  grep "\\.js$" "'"$OUT"'/urls.txt" > "'"$OUT"'/js_files.txt"
'

# ParamSpider
if command -v paramspider >/dev/null 2>&1; then
  run "ParamSpider" paramspider -d "$TARGET" -o "$OUT/paramspider.txt" -w
  cat "$OUT/paramspider.txt" "$OUT/urls.txt" | sort -u > "$OUT/urls.tmp" && mv "$OUT/urls.tmp" "$OUT/urls.txt"
else STEP_INDEX=$((STEP_INDEX+1)); show_progress; fi

# Katana
if command -v katana >/dev/null 2>&1; then
  run "Katana crawl" katana -silent -list "$OUT/resolved.txt" -jc -o "$OUT/urls_katana.txt"
  cat "$OUT/urls_katana.txt" "$OUT/urls.txt" | sort -u > "$OUT/urls.merge" && mv "$OUT/urls.merge" "$OUT/urls.txt"
else STEP_INDEX=$((STEP_INDEX+1)); show_progress; fi

### Bughunt scans ------------------------------------------------------------
[[ -f "$OUT/subdomains.txt" ]] && run "Nuclei takeovers" nuclei -silent -rl $NUCLEI_RATELIMIT -t takeovers/ -l "$OUT/subdomains.txt" -o "$BUG/takeovers_nuclei.txt"
command -v subzy >/dev/null && run "Subzy takeovers" subzy run --targets "$OUT/subdomains.txt" --hide_fails -o "$BUG/takeovers_subzy.txt"

[[ -f "$OUT/resolved.txt" ]] && run "Nuclei exposures" nuclei -silent -rl $NUCLEI_RATELIMIT -t exposures/ -l "$OUT/resolved.txt" -o "$BUG/exposures.txt"
[[ -f "$OUT/resolved.txt" ]] && run "Nuclei default logins" nuclei -silent -rl $NUCLEI_RATELIMIT -t default-logins/ -l "$OUT/resolved.txt" -o "$BUG/default_logins.txt"

[[ -f "$OUT/params_xss.txt" ]] && run "Dalfox XSS" dalfox file "$OUT/params_xss.txt" --worker=$DLW --skip-bav -o "$BUG/dalfox_xss.txt"

[[ -f "$OUT/params_sqli.txt" ]] && run "SQLmap SQLi" sqlmap -m "$OUT/params_sqli.txt" --batch --risk=2 --level=2 --threads=$SQL_T --output-dir="$BUG/sqlmap_out"

if command -v feroxbuster >/dev/null 2>&1 && [[ -f "$OUT/resolved.txt" ]]; then
  run "Feroxbuster brute" bash -c 'head -n 20 "'"$OUT"'/resolved.txt" | xargs -I{} -P5 feroxbuster -q -t '"$FEROX_T"' -u https://{} -w '"$large"' -o "'"$BUG"'/ferox_{}.txt"'
else STEP_INDEX=$((STEP_INDEX+1)); show_progress; fi

if [[ -f "$OUT/js_files.txt" ]]; then
  run "SecretFinder JS" python3 $(which SecretFinder.py 2>/dev/null || echo SecretFinder.py) -i "$OUT/js_files.txt" -o cli > "$BUG/js_secrets.txt"
  while read -r jsurl; do run "Trufflehog JS" bash -c "curl -s '$jsurl' | trufflehog stdin --regex --entropy=False --json >> '$BUG/trufflehog.json'"; done < "$OUT/js_files.txt"
else STEP_INDEX=$((STEP_INDEX+2)); show_progress; fi

[[ -f "$OUT/resolved.txt" ]] && run "Corsy" corsy -i "$OUT/resolved.txt" -o "$BUG/corsy_report"

if [[ -f "$OUT/resolved.txt" ]]; then
  run "FFUF brute" bash -c 'head -n 30 "'"$OUT"'/resolved.txt" | while read -r h; do ffuf -mc all -t '"$TH_FFUF"' -w '"$med"' -u "https://${h}/FUZZ" -o "'"$BUG"'/ffuf_${h//[^a-zA-Z0-9]/_}.json" 2>/dev/null; done'
else STEP_INDEX=$((STEP_INDEX+1)); show_progress; fi

if [[ -f "$OUT/ports.txt" ]]; then
  awk '{print "http://"$1":"$2}' "$OUT/ports.txt" > "$BUG/hostports.txt"
  run "Nuclei service CVEs" nuclei -silent -rl $NUCLEI_RATELIMIT -t cves/ -l "$BUG/hostports.txt" -o "$BUG/service_cves.txt"
else STEP_INDEX=$((STEP_INDEX+1)); show_progress; fi

# Testssl on top 10 hosts
if command -v testssl.sh >/dev/null 2>&1 && [[ -f "$OUT/resolved.txt" ]]; then
  run "TestSSL top hosts" bash -c 'head -n 10 "'"$OUT"'/resolved.txt" | xargs -I{} -P3 testssl.sh --fast --quiet https://{} > "'"$BUG"'/testssl_{}.txt"'
else STEP_INDEX=$((STEP_INDEX+1)); show_progress; fi

if command -v interactsh-client >/dev/null 2>&1 && [[ -f "$OUT/params_ssrf.txt" ]]; then
  run "Interactsh client" interactsh-client -q -o "$BUG/int.url"
  IURL=$(cat "$BUG/int.url" 2>/dev/null || echo "")
  [[ -n "$IURL" ]] && run "Nuclei blind SSRF" nuclei -silent -rl $NUCLEI_RATELIMIT -t vulnerabilities/ -l "$OUT/params_ssrf.txt" -interactsh-url "$IURL" -o "$BUG/ssrf_blind.txt"
else STEP_INDEX=$((STEP_INDEX+1)); show_progress; fi

ok "✅ Scan complete — results in $BUG"

if [[ -n "${WEBHOOK_URL:-}" ]]; then
  curl -s -X POST -d "✅ BugHunt finished for $TARGET — $(date)" "$WEBHOOK_URL" >/dev/null 2>&1 && info "Webhook sent"
fi
