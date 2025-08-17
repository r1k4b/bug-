#!/usr/bin/env bash
# bughunt_autopilot.sh — One-file automation: install → run → schedule
# ------------------------------------------------------------------
# What it does:
#   - Installs all required tools (apt + Go)  [setup]
#   - Runs a full bug-hunt pipeline            [run]
#   - Schedules daily auto-runs via cron       [schedule]
#   - Removes schedule                         [unschedule]
#   - Shows tool versions & cron status        [status]
#
# Quick start (WSL/Ubuntu):
#   1) chmod +x bughunt_autopilot.sh
#   2) ./bughunt_autopilot.sh setup
#   3) ./bughunt_autopilot.sh run chorcha.net api.chorcha.net
#   4) (optional) ./bughunt_autopilot.sh schedule chorcha.net api.chorcha.net
#
# Output:
#   - WSL:   C:\Users\<You>\Desktop\bughunt_out\
#   - Linux: ./bughunt_out/
#
# Legal: Scan only assets you have explicit permission to test.
set -Eeuo pipefail
shopt -s inherit_errexit

NAME="bughunt_autopilot"
log(){ printf '%(%Y-%m-%d %H:%M:%S)T %s\n' -1 "$*"; }
die(){ echo "✖️  $*" >&2; exit 1; }
usage(){
  cat <<'U'
Usage:
  ./bughunt_autopilot.sh setup
  ./bughunt_autopilot.sh run <domain-or-url> [more ...]
  ./bughunt_autopilot.sh schedule <domain-or-url> [more ...]
  ./bughunt_autopilot.sh unschedule
  ./bughunt_autopilot.sh status

If you omit targets for "run"/"schedule", the script will look for /mnt/c/bug/targets.txt (WSL)
or ./targets.txt (Linux) with one domain per line.
U
}

ACTION="${1:-run}"; shift || true

# --- Environment & paths ---
is_wsl=false; grep -qi microsoft /proc/version 2>/dev/null && is_wsl=true
# Workdir for configs/cron log
if $is_wsl; then
  WORKDIR="/mnt/c/bug"
else
  WORKDIR="$PWD"
fi
mkdir -p "$WORKDIR"

# Output base
if $is_wsl && [[ -d /mnt/c/Users ]]; then
  # pick first Desktop found
  BASE_DIR=""
  for u in "$(/bin/ls -1 /mnt/c/Users 2>/dev/null)"; do
    if [[ -d "/mnt/c/Users/$u/Desktop" ]]; then BASE_DIR="/mnt/c/Users/$u/Desktop/bughunt_out"; break; fi
  done
  [[ -z "$BASE_DIR" ]] && BASE_DIR="${PWD}/bughunt_out"
else
  BASE_DIR="${PWD}/bughunt_out"
fi
mkdir -p "$BASE_DIR"

TARGETS_TXT="$WORKDIR/targets.txt"
CRON_LOG="$WORKDIR/${NAME}_cron.log"
SELF_PATH="$(readlink -f "$0" 2>/dev/null || python3 - <<'PY' 2>/dev/null
import os,sys
print(os.path.abspath(sys.argv[1]))
PY
"$0"
)"
[[ -z "${SELF_PATH:-}" ]] && SELF_PATH="$0"

# --- Required / Optional tools ---
REQ=(subfinder dnsx httpx waybackurls gau gf nuclei jq zip)
OPT=(katana nmap naabu interactsh-client subzy ffuf)

ensure_path(){
  # ensure Go bin on PATH if present
  [[ -d "$HOME/go/bin" ]] && export PATH="$PATH:$HOME/go/bin"
}

install_tools(){
  ensure_path
  MISSING=(); for t in "${REQ[@]}"; do command -v "$t" &>/dev/null || MISSING+=("$t"); done
  if (( ${#MISSING[@]} )); then
    log "[setup] Installing apt packages + Go tools (missing: ${MISSING[*]})"
    if command -v apt &>/dev/null; then
      sudo apt update -y || true
      sudo apt install -y jq zip git build-essential curl nmap golang-go seclists cron || true
    else
      die "apt not found. Use an Ubuntu/WSL environment."
    fi
    ensure_path
    # Go tools
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
  else
    log "[setup] All required tools already present."
  fi
}

# --- Helpers ---
to_apex(){ local in="$1" host dots; host="$(echo "$in" | sed -E 's#^[a-zA-Z]+://##' | cut -d'/' -f1 | cut -d':' -f1)"; dots="$(grep -o "\." <<< "$host" | wc -l)"; (( dots >= 2 )) && echo "${host#*.}" || echo "$host"; }

autotune(){
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
  MODE="safe"; if (( CORES>=8 && MEM_GB>=12 && LOSS<5 && AVG_RTT<50 )); then MODE="aggr"; fi
  if [[ "$PROFILE" == "slow" ]] ; then
    HTTPX_THREADS=60; HTTPX_TIMEOUT=10
    NUCLEI_C=30; NUCLEI_RL=80; NUCLEI_TIMEOUT=12
    KATANA_CT=5; KATANA_C=10
    NAABU_RATE=2000
    FFUF_THREADS=20
  else
    HTTPX_THREADS=$(( CORES * 30 )); [[ $HTTPX_THREADS -lt 120 ]] && HTTPX_THREADS=120; [[ $HTTPX_THREADS -gt 220 ]] && HTTPX_THREADS=220
    HTTPX_TIMEOUT=7
    NUCLEI_C=$(( CORES * 10 )); [[ $NUCLEI_C -lt 50 ]] && NUCLEI_C=50; [[ $NUCLEI_C -gt 100 ]] && NUCLEI_C=100
    NUCLEI_RL=140; NUCLEI_TIMEOUT=10
    KATANA_CT=10; KATANA_C=20
    NAABU_RATE=5000
    FFUF_THREADS=40
  fi
  echo "# autotune: CORES=$CORES MEM=${MEM_GB}GB LOSS=${LOSS}% RTT=${AVG_RTT}ms → profile=$PROFILE nmap_mode=$MODE"
}

ensure_reqs(){
  MISSING=(); for t in "${REQ[@]}"; do command -v "$t" &>/dev/null || MISSING+=("$t"); done
  (( ${#MISSING[@]} )) && die "Missing tools: ${MISSING[*]}. Run: ./$(basename "$SELF_PATH") setup"
}

build_targets(){
  DOMAINS=()
  if (( $# )); then
    for raw in "$@"; do d="$(to_apex "$raw" | tr -d '\r\n ')"; [[ -n "$d" ]] && DOMAINS+=("$d"); done
  elif [[ -f "$TARGETS_TXT" ]]; then
    while IFS= read -r raw; do d="$(to_apex "$raw" | tr -d '\r\n ')"; [[ -n "$d" ]] && DOMAINS+=("$d"); done < "$TARGETS_TXT"
  else
    echo "⚠️  No targets provided. Using example: chorcha.net"; DOMAINS=("chorcha.net")
  fi
  # uniq
  declare -A S; DOMAINS_U=(); for d in "${DOMAINS[@]}"; do [[ -z "${S[$d]+x}" ]] && { DOMAINS_U+=("$d"); S[$d]=1; }; done
  DOMAINS=("${DOMAINS_U[@]}")
  (( ${#DOMAINS[@]} )) || die "No valid domains."
}

run_pipeline(){
  autotune; echo "$(autotune)" >/dev/null  # ensure vars are set
  # Versions
  { echo "# Tool versions @ $(date -Is)"; for t in "${REQ[@]}" "${OPT[@]}"; do command -v "$t" &>/dev/null && { printf "%-22s " "$t"; "$t" -version 2>/dev/null || "$t" --version 2>/dev/null || "$t" -V 2>/dev/null || echo; }; done; } > "$BASE_DIR/tool_versions.txt"
  SUMMARY="$BASE_DIR/summary_$(date +%Y%m%d_%H%M%S).csv"; echo "domain,live_hosts,nuclei_findings,nmap_open_services,subzy_findings,ffuf_hits,run_dir" > "$SUMMARY"

  for domain in "${DOMAINS[@]}"; do
    ts="$(date +%Y%m%d_%H%M%S)"; RUN_DIR="$BASE_DIR/${domain}_scan_${ts}"; LOG="$RUN_DIR/live.log"
    mkdir -p "$RUN_DIR"; : > "$LOG"; log "[*] $domain → $RUN_DIR" | tee -a "$LOG"

    log "[1/11] subfinder" | tee -a "$LOG"
    subfinder -d "$domain" -silent | sort -u | tee "$RUN_DIR/subdomains.txt" >/dev/null

    log "[2/11] dnsx" | tee -a "$LOG"
    dnsx -l "$RUN_DIR/subdomains.txt" -silent -a -aaaa -cname -resp-only -retries 3 -t 120 | sort -u > "$RUN_DIR/resolved.txt"
    dnsx -l "$RUN_DIR/subdomains.txt" -silent -a -aaaa -resp-only | sort -u > "$RUN_DIR/ips.txt" || true

    log "[3/11] httpx (threads=$HTTPX_THREADS timeout=${HTTPX_TIMEOUT}s)" | tee -a "$LOG"
    httpx -l "$RUN_DIR/resolved.txt" -silent -follow-redirects -title -status-code -tech-detect -json -threads "$HTTPX_THREADS" -timeout "$HTTPX_TIMEOUT" \
      | tee "$RUN_DIR/live.jsonl" >/dev/null
    jq -r 'select(.scheme and .input) | .scheme + "://" + .input' "$RUN_DIR/live.jsonl" | sort -u > "$RUN_DIR/live.txt"

    log "[4/11] waybackurls + gau + katana" | tee -a "$LOG"
    (cat "$RUN_DIR/subdomains.txt" | waybackurls; cat "$RUN_DIR/subdomains.txt" | gau) | sort -u > "$RUN_DIR/urls_history.txt"
    if command -v katana &>/dev/null; then
      log "       katana (ct=$KATANA_CT, c=$KATANA_C)" | tee -a "$LOG"
      katana -u "https://$domain" -silent -jc -eff -kf -ef png,jpg,gif,svg,woff,woff2 -d 2 -ps -ct "$KATANA_CT" -c "$KATANA_C" \
        | sort -u > "$RUN_DIR/urls_crawl.txt"
    fi

    log "[5/11] gf patterns" | tee -a "$LOG"
    pushd "$RUN_DIR" >/dev/null
    if gf -list >/dev/null 2>&1; then gf -list | while read -r pat; do gf "$pat" < urls_history.txt > "gf_${pat}.txt"; done; fi
    popd >/dev/null

    log "[6/11] nuclei (-c $NUCLEI_C -rl $NUCLEI_RL timeout=${NUCLEI_TIMEOUT}s)" | tee -a "$LOG"
    nuclei -l "$RUN_DIR/live.txt" -severity info,low,medium,high,critical -rl "$NUCLEI_RL" -c "$NUCLEI_C" -timeout "$NUCLEI_TIMEOUT" -retries 2 \
      -stats -stats-json -o "$RUN_DIR/nuclei_report.txt" -silent | sed 's/^/[nuclei] /' | tee -a "$LOG"

    if command -v naabu &>/dev/null; then
      log "[7/11] naabu (rate=$NAABU_RATE) — ONLY if scope allows" | tee -a "$LOG"
      naabu -l "$RUN_DIR/resolved.txt" -top-ports 100 -rate "$NAABU_RATE" -o "$RUN_DIR/ports.txt" -silent || true
    fi

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

    if command -v subzy &>/dev/null; then
      log "[9/11] subzy (takeover)" | tee -a "$LOG"
      subzy run --targets "$RUN_DIR/subdomains.txt" --output "$RUN_DIR/subzy_takeover.txt" || true
    fi

    FF_HITS=0
    if command -v ffuf &>/dev/null; then
      log "[10/11] ffuf (threads=$FFUF_THREADS)" | tee -a "$LOG"
      mkdir -p "$RUN_DIR/ffuf"
      # select a wordlist
      FF_WORDLIST=""
      for wl in /usr/share/seclists/Discovery/Web-Content/common.txt /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt; do
        [[ -f "$wl" ]] && FF_WORDLIST="$wl" && break
      done
      if [[ -z "$FF_WORDLIST" ]]; then
        FF_WORDLIST="$RUN_DIR/_mini_wordlist.txt"
        printf "admin\nlogin\napi\nassets\nuploads\nbackup\nconfig\ndebug\nold\ntest\n" > "$FF_WORDLIST"
      fi
      while read -r url; do
        [[ -z "$url" ]] && continue
        host="$(echo "$url" | sed -E 's#^[a-zA-Z]+://##' | cut -d'/' -f1 | cut -d':' -f1)"
        out="$RUN_DIR/ffuf/${host//[^A-Za-z0-9_.-]/_}.json"
        ffuf -u "${url%/}/FUZZ" -w "$FF_WORDLIST" -t "$FFUF_THREADS" -mc 200,204,301,302,307,401,403 -of json -o "$out" -timeout 10 -replay-proxy "" 2>/dev/null || true
        hits="$(jq '[.results[]?] | length' "$out" 2>/dev/null || echo 0)"
        FF_HITS=$(( FF_HITS + hits ))
      done < "$RUN_DIR/live.txt"
    fi

    if command -v interactsh-client &>/dev/null; then
      echo "tip: interactsh-client -json -o \"$RUN_DIR/interactsh.jsonl\"" | tee -a "$LOG"
    fi

    local livec="0" nuc="0" nmapc="0" subc="0"
    [[ -f "$RUN_DIR/live.txt" ]] && livec="$(wc -l < "$RUN_DIR/live.txt" | tr -d ' ')"
    [[ -f "$RUN_DIR/nuclei_report.txt" ]] && nuc="$(wc -l < "$RUN_DIR/nuclei_report.txt" | tr -d ' ')"
    [[ -d "$RUN_DIR/nmap" ]] && nmapc="$(grep -h ' open ' "$RUN_DIR"/nmap/*.gnmap 2>/dev/null | wc -l | tr -d ' ')"
    [[ -f "$RUN_DIR/subzy_takeover.txt" ]] && subc="$(wc -l < "$RUN_DIR/subzy_takeover.txt" | tr -d ' ')"
    echo "$domain,${livec:-0},${nuc:-0},${nmapc:-0},${subc:-0},${FF_HITS:-0},$RUN_DIR" >> "$SUMMARY"

    (cd "$BASE_DIR" && zip -r "${domain}_report_${ts}.zip" "$(basename "$RUN_DIR")" >/dev/null || true)
    log "✅ $domain done → $RUN_DIR" | tee -a "$LOG"
  done

  ( cd "$BASE_DIR" && zip -r "ALL_RESULTS_$(date +%Y%m%d_%H%M%S).zip" . -i "*_scan_*" -i "summary_*.csv" -i "tool_versions.txt" >/dev/null || true )
  log "🎉 All done. Summary → $SUMMARY"
}

schedule_job(){
  build_targets "$@"
  printf "%s\n" "${DOMAINS[@]}" > "$TARGETS_TXT"
  # Make a tiny wrapper to avoid quoting issues
  RUNNER="$WORKDIR/${NAME}_runner.sh"
  cat > "$RUNNER" <<R
#!/usr/bin/env bash
exec "$SELF_PATH" run
R
  chmod +x "$RUNNER"
  # Add cron entry: daily at 01:00
  ( crontab -l 2>/dev/null | grep -v "$RUNNER" ; echo "0 1 * * * $RUNNER >> $CRON_LOG 2>&1" ) | crontab -
  # Ensure cron service
  if command -v service &>/dev/null; then
    sudo service cron start || true
    sudo systemctl enable cron 2>/dev/null || true
  fi
  log "✅ Scheduled daily 01:00 scan for: ${DOMAINS[*]}"
  log "   Edit targets in: $TARGETS_TXT"
  log "   Cron log:        $CRON_LOG"
}

unschedule_job(){
  RUNNER="$WORKDIR/${NAME}_runner.sh"
  TMP="$(mktemp)"
  crontab -l 2>/dev/null | grep -v "$RUNNER" > "$TMP" || true
  crontab "$TMP" || true
  rm -f "$TMP" "$RUNNER"
  log "🗑️  Removed schedule (if existed)."
}

show_status(){
  ensure_path
  echo "== Versions =="
  for t in "${REQ[@]}" "${OPT[@]}"; do
    if command -v "$t" &>/dev/null; then
      printf "%-20s " "$t"; "$t" -version 2>/dev/null || "$t" --version 2>/dev/null || "$t" -V 2>/dev/null || echo
    else
      printf "%-20s %s\n" "$t" "not found"
    fi
  done
  echo
  echo "== Cron =="
  crontab -l 2>/dev/null | sed 's/^/  /' || echo "  (no crontab)"
  echo
  echo "Targets file: $TARGETS_TXT"
  [[ -f "$TARGETS_TXT" ]] && nl -ba "$TARGETS_TXT" | sed 's/^/  /'
  echo
  echo "Output dir: $BASE_DIR"
}

case "$ACTION" in
  setup)     install_tools ;;
  run)       ensure_reqs; build_targets "$@"; run_pipeline ;;
  schedule)  install_tools; schedule_job "$@" ;;
  unschedule) unschedule_job ;;
  status)    show_status ;;
  *)         usage ;;
esac
