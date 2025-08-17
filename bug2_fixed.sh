#!/usr/bin/env bash
# bughunt_oneclick.sh — Just give URL(s) or domain(s), everything auto.
set -Eeuo pipefail
shopt -s inherit_errexit

usage(){ cat <<'U'
Usage:
  ./bughunt_oneclick.sh https://example.com https://api.example.com
  ./bughunt_oneclick.sh example.com [--no-install] [--no-nmap] [--with-naabu] [--mode safe|aggr] [--base /path/out] [--oob]
U
}

DOMAINS_RAW=(); BASE_DIR=""; AUTO_INSTALL=true; WITH_NMAP=true; WITH_NAABU=false; MODE="safe"; WITH_OOB=false
while [[ $# -gt 0 ]]; do case "$1" in
  --base) BASE_DIR="$2"; shift 2 ;; --no-install) AUTO_INSTALL=false; shift ;;
  --no-nmap) WITH_NMAP=false; shift ;; --with-naabu) WITH_NAABU=true; shift ;;
  --mode) MODE="$2"; shift 2 ;; --oob) WITH_OOB=true; shift ;;
  -h|--help) usage; exit 0 ;; --) shift; break ;;
  -*) echo "Unknown flag: $1"; usage; exit 1 ;;
  *) DOMAINS_RAW+=("$1"); shift ;;
done; done
(( ${#DOMAINS_RAW[@]} == 0 )) && { usage; exit 1; }

is_wsl=false; grep -qi microsoft /proc/version 2>/dev/null && is_wsl=true
if [[ -z "$BASE_DIR" ]]; then
  if $is_wsl && [[ -d /mnt/c/Users ]]; then WINUSER=$(ls /mnt/c/Users | head -n1); BASE_DIR="/mnt/c/Users/${WINUSER}/Desktop/bughunt_out"
  else BASE_DIR="${PWD}/bughunt_out"; fi
fi
mkdir -p "$BASE_DIR"

CORES="$(nproc 2>/dev/null || echo 2)"
MEM_MB="$( (free -m | awk '/^Mem:/ {print $2}') 2>/dev/null || echo 2048 )"
AVG_RTT=50; LOSS=0
if command -v ping &>/dev/null; then
  P="$(ping -c 5 -w 6 -n 1.1.1.1 2>/dev/null || true)"
  LOSS="$(echo "$P" | grep -oE '[0-9]+% packet loss' | grep -oE '^[0-9]+' || echo 0)"
  AVG_RTT="$(echo "$P" | awk -F'/' '/rtt/ {print $5}' | cut -d'.' -f1)"; [[ -z "$AVG_RTT" ]] && AVG_RTT=70
fi
PROFILE="fast"; (( LOSS > 10 )) || (( AVG_RTT > 80 )) && PROFILE="slow"
log(){ printf '%(%Y-%m-%d %H:%M:%S)T %s\n' -1 "$*"; }
log "[autotune] CORES=$CORES MEM=$((MEM_MB/1024))GB LOSS=${LOSS}% RTT=${AVG_RTT}ms → $PROFILE"

if [[ "$PROFILE" == "slow" ]]; then
  HTTPX_THREADS=60; HTTPX_TIMEOUT=10; NUCLEI_C=30; NUCLEI_RL=80; NUCLEI_TIMEOUT=12; KATANA_CT=5; KATANA_C=10; NAABU_RATE=2000
else
  HTTPX_THREADS=$(( CORES * 30 )); [[ $HTTPX_THREADS -lt 120 ]] && HTTPX_THREADS=120; [[ $HTTPX_THREADS -gt 200 ]] && HTTPX_THREADS=200
  HTTPX_TIMEOUT=7; NUCLEI_C=$(( CORES * 10 )); [[ $NUCLEI_C -lt 50 ]] && NUCLEI_C=50; [[ $NUCLEI_C -gt 80 ]] && NUCLEI_C=80
  NUCLEI_RL=120; NUCLEI_TIMEOUT=10; KATANA_CT=10; KATANA_C=20; NAABU_RATE=4000
fi

REQ=(subfinder dnsx httpx waybackurls gau gf nuclei zip jq); OPT=(katana nmap naabu interactsh-client subzy)
MISSING=(); for t in "${REQ[@]}"; do command -v "$t" &>/dev/null || MISSING+=("$t"); done
if (( ${#MISSING[@]} )) && [[ "$AUTO_INSTALL" == "true" ]] && command -v apt &>/dev/null; then
  log "[autoinstall] Missing: ${MISSING[*]} → installing (apt + Go)"
  sudo apt update -y || true
  sudo apt install -y jq zip git build-essential curl nmap golang-go || true
  export PATH="$PATH:$HOME/go/bin"
  go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest || true
  go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest || true
  go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest || true
  go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest || true
  go install -v github.com/projectdiscovery/katana/cmd/katana@latest || true
  go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest || true
  go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest || true
  go install -v github.com/tomnomnom/waybackurls@latest || true
  go install -v github.com/lc/gau/v2/cmd/gau@latest || true
  go install -v github.com/tomnomnom/gf@latest || true
  go install -v github.com/ffuf/ffuf@latest || true
  go install -v github.com/LukaSikic/subzy@latest || true
  mkdir -p "$HOME/.gf" && git clone --depth=1 https://github.com/tomnomnom/gf "$HOME/.gf-tmp" 2>/dev/null || true
  cp -r "$HOME/.gf-tmp/examples/"* "$HOME/.gf/" 2>/dev/null || true; rm -rf "$HOME/.gf-tmp" || true
fi
MISSING=(); for t in "${REQ[@]}"; do command -v "$t" &>/dev/null || MISSING+=("$t"); done
(( ${#MISSING[@]} )) && { echo "✖️ Missing required tools: ${MISSING[*]}"; exit 1; }

to_apex(){ local in="$1"; local host; host="$(echo "$in" | sed -E 's#^[a-zA-Z]+://##' | cut -d'/' -f1 | cut -d':' -f1)"; local dots; dots="$(grep -o "\." <<< "$host" | wc -l)"; (( dots >= 2 )) && echo "${host#*.}" || echo "$host"; }
declare -A seen; DOMAINS=(); for raw in "${DOMAINS_RAW[@]}"; do d="$(to_apex "$raw" | tr -d '\r\n ')"; [[ -z "$d" ]] && continue; [[ -n "${seen[$d]+x}" ]] || { DOMAINS+=("$d"); seen[$d]=1; }; done
(( ${#DOMAINS[@]} == 0 )) && { echo "No valid domains."; exit 1; }

{ echo "# Tool versions @ $(date -Is)"; for t in "${REQ[@]}" "${OPT[@]}"; do command -v "$t" &>/dev/null && { printf "%-22s " "$t"; "$t" -version 2>/dev/null || "$t" --version 2>/dev/null || "$t" -V 2>/dev/null || echo; }; done; } > "$BASE_DIR/tool_versions.txt"
SUMMARY="$BASE_DIR/summary_$(date +%Y%m%d_%H%M%S).csv"; echo "domain,live_hosts,nuclei_findings,nmap_open_services,subzy_findings,run_dir" > "$SUMMARY"

run_domain(){
  local domain="$1"; local ts="$(date +%Y%m%d_%H%M%S)"; local RUN_DIR="$BASE_DIR/${domain}_scan_${ts}"; local LOG="$RUN_DIR/live.log"
  mkdir -p "$RUN_DIR"; : > "$LOG"; log "[*] $domain → $RUN_DIR" | tee -a "$LOG"
  log "[1/9] subfinder" | tee -a "$LOG"; subfinder -d "$domain" -silent | sort -u | tee "$RUN_DIR/subdomains.txt" >/dev/null
  log "[2/9] dnsx" | tee -a "$LOG"; dnsx -l "$RUN_DIR/subdomains.txt" -silent -a -aaaa -cname -resp-only -retries 3 -t 120 | sort -u > "$RUN_DIR/resolved.txt"; dnsx -l "$RUN_DIR/subdomains.txt" -silent -a -aaaa -resp-only | sort -u > "$RUN_DIR/ips.txt" || true
  log "[3/9] httpx (threads=$HTTPX_THREADS timeout=${HTTPX_TIMEOUT}s)" | tee -a "$LOG"; httpx -l "$RUN_DIR/resolved.txt" -silent -follow-redirects -title -status-code -tech-detect -json -threads "$HTTPX_THREADS" -timeout "$HTTPX_TIMEOUT" | tee "$RUN_DIR/live.jsonl" >/dev/null
  jq -r 'select(.scheme and .input) | .scheme + "://" + .input' "$RUN_DIR/live.jsonl" | sort -u > "$RUN_DIR/live.txt"
  log "[4/9] waybackurls + gau (+katana if present)" | tee -a "$LOG"; (cat "$RUN_DIR/subdomains.txt" | waybackurls; cat "$RUN_DIR/subdomains.txt" | gau) | sort -u > "$RUN_DIR/urls_history.txt"
  if command -v katana &>/dev/null; then log "       katana (light)" | tee -a "$LOG"; katana -u "https://$domain" -silent -jc -eff -kf -ef png,jpg,gif,svg,woff,woff2 -d 2 -ps -ct ${KATANA_CT:-10} -c ${KATANA_C:-20} | sort -u > "$RUN_DIR/urls_crawl.txt"; fi
  log "[5/9] gf patterns" | tee -a "$LOG"; pushd "$RUN_DIR" >/dev/null; if gf -list >/dev/null 2>&1; then gf -list | while read -r pat; do gf "$pat" < urls_history.txt > "gf_${pat}.txt"; done; fi; popd >/dev/null
  log "[6/9] nuclei (-c ${NUCLEI_C} -rl ${NUCLEI_RL})" | tee -a "$LOG"; nuclei -l "$RUN_DIR/live.txt" -severity info,low,medium,high,critical -rl "${NUCLEI_RL}" -c "${NUCLEI_C}" -timeout "${NUCLEI_TIMEOUT}" -retries 2 -stats -stats-json -o "$RUN_DIR/nuclei_report.txt" -silent | sed 's/^/[nuclei] /' | tee -a "$LOG"
  if [[ "$WITH_NAABU" == "true" ]] && command -v naabu &>/dev/null; then log "[7/9] naabu (rate=${NAABU_RATE})" | tee -a "$LOG"; naabu -l "$RUN_DIR/resolved.txt" -top-ports 100 -rate "${NAABU_RATE}" -o "$RUN_DIR/ports.txt" -silent || true; fi
  if [[ "$WITH_NMAP" == "true" ]] && command -v nmap &>/dev/null; then mkdir -p "$RUN_DIR/nmap"; WEB_PORTS="80,443,8080,8443,8000,8008,8888,9000,9001,9002,9443"
    case "$MODE" in
      safe) log "[8/9] nmap SAFE" | tee -a "$LOG"; [[ -s "$RUN_DIR/ips.txt" ]] && nmap -sV -sC -Pn -T3 -F -iL "$RUN_DIR/ips.txt" -oA "$RUN_DIR/nmap/nmap_fast" || true
            [[ -s "$RUN_DIR/ips.txt" ]] && nmap -sV -Pn -T3 -p "$WEB_PORTS" -iL "$RUN_DIR/ips.txt" --script "http-title,http-headers,http-security-headers,ssl-cert,ssl-enum-ciphers,http-enum" -oA "$RUN_DIR/nmap/nmap_web" || true ;;
      aggr) log "[8/9] nmap AGGR" | tee -a "$LOG"
            if [[ -f "$RUN_DIR/ports.txt" && -s "$RUN_DIR/ports.txt" ]]; then
              awk -F: '{p[$1]=p[$1]","$2} END{for(h in p){gsub(/^,/, "", p[h]); print h" "p[h]}}' "$RUN_DIR/ports.txt" > "$RUN_DIR/nmap/targets_ports.txt" || true
              while read -r host ports; do safe_host="${host//[^A-Za-z0-9_.-]/_}"; nmap -sV -sC -Pn -T3 -p "$ports" "$host" -oA "$RUN_DIR/nmap/nmap_${safe_host}" || true; done < "$RUN_DIR/nmap/targets_ports.txt"
            else
              [[ -s "$RUN_DIR/ips.txt" ]] && nmap -sV -sC -Pn -T3 -F -iL "$RUN_DIR/ips.txt" -oA "$RUN_DIR/nmap/nmap_fast" || true
              [[ -s "$RUN_DIR/ips.txt" ]] && nmap -sV -Pn -T3 -p "$WEB_PORTS" -iL "$RUN_DIR/ips.txt" --script "http-title,http-headers,http-security-headers,ssl-cert,ssl-enum-ciphers,http-enum,http-methods,http-robots.txt" -oA "$RUN_DIR/nmap/nmap_web" || true
            fi ;;
    esac
  fi
  if [[ "$WITH_OOB" == "true" ]] && command -v interactsh-client &>/dev/null; then echo "tip: interactsh-client -json -o \"$RUN_DIR/interactsh.jsonl\"" | tee -a "$LOG"; fi
  if command -v subzy &>/dev/null; then log "subdomain takeover (subzy)" | tee -a "$LOG"; subzy run --targets "$RUN_DIR/subdomains.txt" --output "$RUN_DIR/subzy_takeover.txt" || true; fi
  local livec="0" nuc="0" nmapc="0" subc="0"; [[ -f "$RUN_DIR/live.txt" ]] && livec="$(wc -l < "$RUN_DIR/live.txt" | tr -d ' ')"; [[ -f "$RUN_DIR/nuclei_report.txt" ]] && nuc="$(wc -l < "$RUN_DIR/nuclei_report.txt" | tr -d ' ')"
  [[ -d "$RUN_DIR/nmap" ]] && nmapc="$(grep -h ' open ' "$RUN_DIR"/nmap/*.gnmap 2>/dev/null | wc -l | tr -d ' ')"; [[ -f "$RUN_DIR/subzy_takeover.txt" ]] && subc="$(wc -l < "$RUN_DIR/subzy_takeover.txt" | tr -d ' ')"
  echo "$domain,${livec:-0},${nuc:-0},${nmapc:-0},${subc:-0},$RUN_DIR" >> "$SUMMARY"
  (cd "$BASE_DIR" && zip -r "${domain}_report_${ts}.zip" "$(basename "$RUN_DIR")" >/dev/null || true)
  log "✅ $domain done → $RUN_DIR" | tee -a "$LOG"
}

for d in "${DOMAINS_RAW[@]}"; do true; done
# normalize to apex
DOMAINS=(); declare -A s; for raw in "${DOMAINS_RAW[@]}"; do d="$(to_apex "$raw")"; [[ -n "${s[$d]+x}" ]] || { DOMAINS+=("$d"); s[$d]=1; }; done
for d in "${DOMAINS[@]}"; do run_domain "$d"; done
( cd "$BASE_DIR" && zip -r "ALL_RESULTS_$(date +%Y%m%d_%H%M%S).zip" . -i "*_scan_*" -i "summary_*.csv" -i "tool_versions.txt" >/dev/null || true )
log "🎉 All done. Summary → $SUMMARY"
echo "Only scan targets you have permission to test."
