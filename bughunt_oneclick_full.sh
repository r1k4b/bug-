#!/usr/bin/env bash
# bughunt_oneclick_full.sh — URL/Domain দিলেই ফুল-পাওয়ার অটো রান
# - No flags needed. All optional tools ON by default (naabu, nmap, katana, subzy).
# - Auto-install missing deps (apt + Go). Uses ffuf if Seclists is present.
# - Self-tunes based on CPU/RAM/Network; auto-picks nmap safe/aggr.
# - Output: Desktop/bughunt_out on WSL, otherwise ./bughunt_out
#
# Usage:
#   ./bughunt_oneclick_full.sh https://example.com api.example.com
#
set -Eeuo pipefail
shopt -s inherit_errexit

usage(){ echo "Usage: $0 <domain-or-url> [more ...]"; exit 1; }
log(){ printf '%(%Y-%m-%d %H:%M:%S)T %s\n' -1 "$*"; }
die(){ echo "✖️  $*" >&2; exit 1; }

(( $# == 0 )) && usage
DOMAINS_RAW=("$@")

# --- Environment/Output dir ---
is_wsl=false; grep -qi microsoft /proc/version 2>/dev/null && is_wsl=true
if $is_wsl && [[ -d /mnt/c/Users ]]; then
  for u in "$(/bin/ls -1 /mnt/c/Users 2>/dev/null)"; do
    if [[ -d "/mnt/c/Users/$u/Desktop" ]]; then BASE_DIR="/mnt/c/Users/$u/Desktop/bughunt_out"; break; fi
  done
  [[ -z "${BASE_DIR:-}" ]] && BASE_DIR="${PWD}/bughunt_out"
else
  BASE_DIR="${PWD}/bughunt_out"
fi
mkdir -p "$BASE_DIR"

# --- Autotune ---
CORES="$(nproc 2>/dev/null || echo 2)"
MEM_MB="$( (free -m | awk '/^Mem:/ {print $2}') 2>/dev/null || echo 2048 )"
MEM_GB=$(( MEM_MB/1024 ))
AVG_RTT=50; LOSS=0
if command -v ping &>/dev/null; then
  P="$(ping -c 5 -w 6 -n 1.1.1.1 2>/dev/null || true)"
  LOSS="$(echo "$P" | grep -oE '[0-9]+% packet loss' | grep -oE '^[0-9]+' || echo 0)"
  AVG_RTT="$(echo "$P" | awk -F'/' '/rtt/ {print $5}' | cut -d'.' -f1)"; [[ -z "$AVG_RTT" ]] && AVG_RTT=70
fi
PROFILE="fast"; if (( LOSS > 10 )) || (( AVG_RTT > 80 )); then PROFILE="slow"; fi
# auto mode: go aggressive only on strong machines/net
MODE="safe"; if (( CORES>=8 && MEM_GB>=12 && LOSS<5 && AVG_RTT<50 )); then MODE="aggr"; fi
log "[autotune] CORES=$CORES MEM=${MEM_GB}GB LOSS=${LOSS}% RTT=${AVG_RTT}ms → profile=$PROFILE, nmap_mode=$MODE"

if [[ "$PROFILE" == "slow" ]] ; then
  HTTPX_THREADS=60; HTTPX_TIMEOUT=10
  NUCLEI_C=30; NUCLEI_RL=80; NUCLEI_TIMEOUT=12
  KATANA_CT=5; KATANA_C=10
  NAABU_RATE=2000
  FFUF_THREADS=20
else
  HTTPX_THREADS=$(( CORES * 30 )); [[ $HTTPX_THREADS -lt 120 ]] && HTTPX_THREADS=120; [[ $HTTPX_THREADS -gt 220 ]] && HTTPX_THREADS=220
  HTTPX_TIMEOUT=7
  NUCLEI_C=$(( CORES * 10 )); [[ $NUCLEI_C -lt 50 ]] && NUCLEI_C=50; [[ $NUCLEI_C -gt 100 ]] && $NUCLEI_C=100
  NUCLEI_RL=140; NUCLEI_TIMEOUT=10
  KATANA_CT=10; KATANA_C=20
  NAABU_RATE=5000
  FFUF_THREADS=40
fi

# --- Requirements ---
REQ=(subfinder dnsx httpx waybackurls gau gf nuclei jq zip)
OPT=(katana nmap naabu interactsh-client subzy ffuf)
MISSING=(); for t in "${REQ[@]}"; do command -v "$t" &>/dev/null || MISSING+=("$t"); done

log "[setup] Checking tools…"
if (( ${#MISSING[@]} )) && command -v apt &>/dev/null; then
  log "[autoinstall] Missing: ${MISSING[*]} → installing (apt + Go)"
  sudo apt update -y || true
  sudo apt install -y jq zip git build-essential curl nmap golang-go seclists || true
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
  # gf patterns
  mkdir -p "$HOME/.gf" && git clone --depth=1 https://github.com/tomnomnom/gf "$HOME/.gf-tmp" 2>/dev/null || true
  cp -r "$HOME/.gf-tmp/examples/"* "$HOME/.gf/" 2>/dev/null || true
  rm -rf "$HOME/.gf-tmp" || true
fi
# verify required again
MISSING=(); for t in "${REQ[@]}"; do command -v "$t" &>/dev/null || MISSING+=("$t"); done
(( ${#MISSING[@]} )) && die "Missing required tools: ${MISSING[*]}"

# ffuf wordlist
FF_WORDLIST=""
for wl in \
  /usr/share/seclists/Discovery/Web-Content/common.txt \
  /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt \
  ; do [[ -f "$wl" ]] && FF_WORDLIST="$wl" && break; done
if [[ -z "$FF_WORDLIST" ]]; then
  # tiny fallback
  FF_WORDLIST="$BASE_DIR/_mini_wordlist.txt"
  cat > "$FF_WORDLIST" <<'W'
admin
login
api
assets
uploads
backup
config
debug
old
test
W
fi

# --- Helpers ---
to_apex(){ local in="$1" host dots; host="$(echo "$in" | sed -E 's#^[a-zA-Z]+://##' | cut -d'/' -f1 | cut -d':' -f1)"; dots="$(grep -o "\." <<< "$host" | wc -l)"; (( dots >= 2 )) && echo "${host#*.}" || echo "$host"; }
declare -A SEEN; DOMAINS=(); for raw in "${DOMAINS_RAW[@]}"; do d="$(to_apex "$raw" | tr -d '\r\n ')"; [[ -z "$d" ]] && continue; [[ -n "${SEEN[$d]+x}" ]] || { DOMAINS+=("$d"); SEEN[$d]=1; }; done
{ echo "# Tool versions @ $(date -Is)"; for t in "${REQ[@]}" "${OPT[@]}"; do command -v "$t" &>/dev/null && { printf "%-22s " "$t"; "$t" -version 2>/dev/null || "$t" --version 2>/dev/null || "$t" -V 2>/dev/null || echo; }; done; } > "$BASE_DIR/tool_versions.txt"
SUMMARY="$BASE_DIR/summary_$(date +%Y%m%d_%H%M%S).csv"; echo "domain,live_hosts,nuclei_findings,nmap_open_services,subzy_findings,ffuf_hits,run_dir" > "$SUMMARY"

run_domain(){
  local domain="$1" ts RUN_DIR LOG WEB_PORTS; ts="$(date +%Y%m%d_%H%M%S)"; RUN_DIR="$BASE_DIR/${domain}_scan_${ts}"; LOG="$RUN_DIR/live.log"
  mkdir -p "$RUN_DIR"; : > "$LOG"; log "[*] $domain → $RUN_DIR" | tee -a "$LOG"

  # 1) subfinder
  log "[1/11] subfinder" | tee -a "$LOG"
  subfinder -d "$domain" -silent | sort -u | tee "$RUN_DIR/subdomains.txt" >/dev/null

  # 2) dnsx
  log "[2/11] dnsx" | tee -a "$LOG"
  dnsx -l "$RUN_DIR/subdomains.txt" -silent -a -aaaa -cname -resp-only -retries 3 -t 120 | sort -u > "$RUN_DIR/resolved.txt"
  dnsx -l "$RUN_DIR/subdomains.txt" -silent -a -aaaa -resp-only | sort -u > "$RUN_DIR/ips.txt" || true

  # 3) httpx
  log "[3/11] httpx (threads=$HTTPX_THREADS timeout=${HTTPX_TIMEOUT}s)" | tee -a "$LOG"
  httpx -l "$RUN_DIR/resolved.txt" -silent -follow-redirects -title -status-code -tech-detect -json -threads "$HTTPX_THREADS" -timeout "$HTTPX_TIMEOUT" \
    | tee "$RUN_DIR/live.jsonl" >/dev/null
  jq -r 'select(.scheme and .input) | .scheme + "://" + .input' "$RUN_DIR/live.jsonl" | sort -u > "$RUN_DIR/live.txt"

  # 4) URLs discovery
  log "[4/11] waybackurls + gau + katana" | tee -a "$LOG"
  (cat "$RUN_DIR/subdomains.txt" | waybackurls; cat "$RUN_DIR/subdomains.txt" | gau) | sort -u > "$RUN_DIR/urls_history.txt"
  if command -v katana &>/dev/null; then
    log "       katana (ct=$KATANA_CT, c=$KATANA_C)" | tee -a "$LOG"
    katana -u "https://$domain" -silent -jc -eff -kf -ef png,jpg,gif,svg,woff,woff2 -d 2 -ps -ct "$KATANA_CT" -c "$KATANA_C" \
      | sort -u > "$RUN_DIR/urls_crawl.txt"
  fi

  # 5) gf
  log "[5/11] gf patterns" | tee -a "$LOG"
  pushd "$RUN_DIR" >/dev/null
  if gf -list >/dev/null 2>&1; then gf -list | while read -r pat; do gf "$pat" < urls_history.txt > "gf_${pat}.txt"; done; fi
  popd >/dev/null

  # 6) nuclei
  log "[6/11] nuclei (-c $NUCLEI_C -rl $NUCLEI_RL timeout=${NUCLEI_TIMEOUT}s)" | tee -a "$LOG"
  nuclei -l "$RUN_DIR/live.txt" -severity info,low,medium,high,critical -rl "$NUCLEI_RL" -c "$NUCLEI_C" -timeout "$NUCLEI_TIMEOUT" -retries 2 \
    -stats -stats-json -o "$RUN_DIR/nuclei_report.txt" -silent | sed 's/^/[nuclei] /' | tee -a "$LOG"

  # 7) naabu (ports)
  if command -v naabu &>/dev/null; then
    log "[7/11] naabu (rate=$NAABU_RATE) — ONLY if scope allows" | tee -a "$LOG"
    naabu -l "$RUN_DIR/resolved.txt" -top-ports 100 -rate "$NAABU_RATE" -o "$RUN_DIR/ports.txt" -silent || true
  fi

  # 8) nmap
  if command -v nmap &>/dev/null; then
    mkdir -p "$RUN_DIR/nmap"; WEB_PORTS="80,443,8080,8443,8000,8008,8888,9000,9001,9002,9443"
    case "$MODE" in
      safe)
        log "[8/11] nmap SAFE" | tee -a "$LOG"
        [[ -s "$RUN_DIR/ips.txt" ]] && nmap -sV -sC -Pn -T3 -F -iL "$RUN_DIR/ips.txt" -oA "$RUN_DIR/nmap/nmap_fast" || true
        [[ -s "$RUN_DIR/ips.txt" ]] && nmap -sV -Pn -T3 -p "$WEB_PORTS" -iL "$RUN_DIR/ips.txt" \
          --script "http-title,http-headers,http-security-headers,ssl-cert,ssl-enum-ciphers,http-enum" -oA "$RUN_DIR/nmap/nmap_web" || true ;;
      aggr)
        log "[8/11] nmap AGGR (per-host; uses naabu ports if present)" | tee -a "$LOG"
        if [[ -f "$RUN_DIR/ports.txt" && -s "$RUN_DIR/ports.txt" ]]; then
          awk -F: '{p[$1]=p[$1]","$2} END{for(h in p){gsub(/^,/, "", p[h]); print h" "p[h]}}' "$RUN_DIR/ports.txt" > "$RUN_DIR/nmap/targets_ports.txt" || true
          while read -r host ports; do safe_host="${host//[^A-Za-z0-9_.-]/_}"; nmap -sV -sC -Pn -T3 -p "$ports" "$host" -oA "$RUN_DIR/nmap/nmap_${safe_host}" || true; done < "$RUN_DIR/nmap/targets_ports.txt"
        else
          [[ -s "$RUN_DIR/ips.txt" ]] && nmap -sV -sC -Pn -T3 -F -iL "$RUN_DIR/ips.txt" -oA "$RUN_DIR/nmap/nmap_fast" || true
          [[ -s "$RUN_DIR/ips.txt" ]] && nmap -sV -Pn -T3 -p "$WEB_PORTS" -iL "$RUN_DIR/ips.txt" \
            --script "http-title,http-headers,http-security-headers,ssl-cert,ssl-enum-ciphers,http-enum,http-methods,http-robots.txt" -oA "$RUN_DIR/nmap/nmap_web" || true
        fi ;;
    esac
  fi

  # 9) subdomain takeover
  if command -v subzy &>/dev/null; then
    log "[9/11] subzy (takeover)" | tee -a "$LOG"
    subzy run --targets "$RUN_DIR/subdomains.txt" --output "$RUN_DIR/subzy_takeover.txt" || true
  fi

  # 10) ffuf (content discovery on live roots)
  FF_HITS=0
  if command -v ffuf &>/dev/null; then
    log "[10/11] ffuf (wordlist=$(basename "$FF_WORDLIST"), threads=$FFUF_THREADS)" | tee -a "$LOG"
    mkdir -p "$RUN_DIR/ffuf"
    while read -r url; do
      [[ -z "$url" ]] && continue
      host="$(echo "$url" | sed -E 's#^[a-zA-Z]+://##' | cut -d'/' -f1 | cut -d':' -f1)"
      out="$RUN_DIR/ffuf/${host//[^A-Za-z0-9_.-]/_}.json"
      ffuf -u "${url%/}/FUZZ" -w "$FF_WORDLIST" -t "$FFUF_THREADS" -mc 200,204,301,302,307,401,403 -of json -o "$out" -timeout 10 -replay-proxy "" 2>/dev/null || true
      hits="$(jq '[.results[]?] | length' "$out" 2>/dev/null || echo 0)"
      FF_HITS=$(( FF_HITS + hits ))
    done < "$RUN_DIR/live.txt"
  fi

  # 11) interactsh tip
  if command -v interactsh-client &>/dev/null; then
    echo "tip: interactsh-client -json -o \"$RUN_DIR/interactsh.jsonl\"" | tee -a "$LOG"
  fi

  # Summary + zip
  local livec="0" nuc="0" nmapc="0" subc="0"
  [[ -f "$RUN_DIR/live.txt" ]] && livec="$(wc -l < "$RUN_DIR/live.txt" | tr -d ' ')"
  [[ -f "$RUN_DIR/nuclei_report.txt" ]] && nuc="$(wc -l < "$RUN_DIR/nuclei_report.txt" | tr -d ' ')"
  [[ -d "$RUN_DIR/nmap" ]] && nmapc="$(grep -h ' open ' "$RUN_DIR"/nmap/*.gnmap 2>/dev/null | wc -l | tr -d ' ')"
  [[ -f "$RUN_DIR/subzy_takeover.txt" ]] && subc="$(wc -l < "$RUN_DIR/subzy_takeover.txt" | tr -d ' ')"
  echo "$domain,${livec:-0},${nuc:-0},${nmapc:-0},${subc:-0},${FF_HITS:-0},$RUN_DIR" >> "$SUMMARY"

  (cd "$BASE_DIR" && zip -r "${domain}_report_${ts}.zip" "$(basename "$RUN_DIR")" >/dev/null || true)
  log "✅ $domain done → $RUN_DIR" | tee -a "$LOG"
}

for d in "${DOMAINS[@]}"; do run_domain "$d"; done

( cd "$BASE_DIR" && zip -r "ALL_RESULTS_$(date +%Y%m%d_%H%M%S).zip" . -i "*_scan_*" -i "summary_*.csv" -i "tool_versions.txt" >/dev/null || true )
log "🎉 All done. Summary → $SUMMARY"
echo "Reminder: Only scan targets you have explicit permission to test."
