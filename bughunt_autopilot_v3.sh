#!/usr/bin/env bash
# bughunt_autopilot_v3.sh — One-file automation (install → run → schedule) + doctor + highlights
# Usage (any one):
#   ./bughunt_autopilot_v3.sh setup
#   ./bughunt_autopilot_v3.sh run example.com
#   ./bughunt_autopilot_v3.sh schedule example.com api.example.com
#   ./bughunt_autopilot_v3.sh status
#   ./bughunt_autopilot_v3.sh doctor
#   ./bughunt_autopilot_v3.sh highlights example.com   # summarize latest run
#   ./bughunt_autopilot_v3.sh example.com              # auto → run
#
set -Eeuo pipefail
shopt -s inherit_errexit
trap 'e=$?; echo "✖️  ERROR at line ${BASH_LINENO[0]}: ${BASH_COMMAND}" >&2; exit $e' ERR

ACTION="${1:-run}"; shift || true
case "$ACTION" in
  setup|run|schedule|unschedule|status|doctor|highlights) ;;
  *) set -- run "$ACTION" "$@"; ACTION="run" ;;
esac

log(){ printf '%(%Y-%m-%d %H:%M:%S)T %s\n' -1 "$*"; }
die(){ echo "✖️  $*" >&2; exit 1; }

# Env/paths
is_wsl=false; grep -qi microsoft /proc/version 2>/dev/null && is_wsl=true
if $is_wsl; then WORKDIR="/mnt/c/bug"; else WORKDIR="$PWD"; fi; mkdir -p "$WORKDIR"
if $is_wsl && [[ -d /mnt/c/Users ]]; then
  BASE_DIR=""
  for u in "$(/bin/ls -1 /mnt/c/Users 2>/dev/null)"; do
    [[ -d "/mnt/c/Users/$u/Desktop" ]] && BASE_DIR="/mnt/c/Users/$u/Desktop/bughunt_out" && break
  done
  [[ -z "$BASE_DIR" ]] && BASE_DIR="${PWD}/bughunt_out"
else
  BASE_DIR="${PWD}/bughunt_out"
fi
mkdir -p "$BASE_DIR"
TARGETS_TXT="$WORKDIR/targets.txt"
CRON_LOG="$WORKDIR/bughunt_autopilot_cron.log"
if command -v realpath >/dev/null 2>&1; then SELF_PATH="$(realpath "$0")"; elif command -v readlink >/dev/null 2>&1; then SELF_PATH="$(readlink -f "$0" 2>/dev/null || echo "$0")"; else SELF_PATH="$0"; fi
[[ -d "$HOME/go/bin" ]] && export PATH="$PATH:$HOME/go/bin"

REQ=(subfinder dnsx httpx waybackurls gau gf nuclei jq zip)
OPT=(katana nmap naabu interactsh-client subzy ffuf)

install_tools(){
  log "[setup] apt + Go tools"
  command -v apt >/dev/null 2>&1 || die "apt not found (need Ubuntu/WSL)"
  sudo apt update -y || true
  sudo apt install -y jq zip git build-essential curl nmap golang-go seclists cron || true
  export PATH="$PATH:$HOME/go/bin"
  export GOPROXY="${GOPROXY:-https://proxy.golang.org,direct}"
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
  mkdir -p "$HOME/.gf"
  if [[ ! -d "$HOME/.gf/examples" ]]; then
    tmp="$HOME/.gf-tmp-$$"; git clone --depth=1 https://github.com/tomnomnom/gf "$tmp" 2>/dev/null || true
    cp -r "$tmp/examples/"* "$HOME/.gf/" 2>/dev/null || true
    rm -rf "$tmp" || true
  fi
  nuclei -update-templates || true
  log "[setup] done."
}

to_apex(){ local in="$1" host dots; host="$(echo "$in" | sed -E 's#^[a-zA-Z]+://##' | cut -d'/' -f1 | cut -d':' -f1)"; dots="$(grep -o "\." <<< "$host" | wc -l)"; (( dots >= 2 )) && echo "${host#*.}" || echo "$host"; }

autotune(){
  CORES="$(nproc 2>/dev/null || echo 2)"
  MEM_MB="$( (free -m | awk '/^Mem:/ {print $2}') 2>/dev/null || echo 2048 )"
  MEM_GB=$(( MEM_MB/1024 ))
  AVG_RTT=50; LOSS=0
  if command -v ping &>/dev/null; then
    P="$(ping -c 3 -w 5 -n 1.1.1.1 2>/dev/null || true)"
    LOSS="$(echo "$P" | grep -oE '[0-9]+% packet loss' | grep -oE '^[0-9]+' || echo 0)"
    AVG_RTT="$(echo "$P" | awk -F'/' '/rtt/ {print $5}' | cut -d'.' -f1)"; [[ -z "$AVG_RTT" ]] && AVG_RTT=70
  fi
  PROFILE="fast"; if (( LOSS > 10 )) || (( AVG_RTT > 80 )); then PROFILE="slow"; fi
  MODE="safe"; if (( CORES>=8 && MEM_GB>=12 && LOSS<5 && AVG_RTT<50 )); then MODE="aggr"; fi
  if [[ "$PROFILE" == "slow" ]] ; then
    HTTPX_THREADS=60; HTTPX_TIMEOUT=10; NUCLEI_C=30; NUCLEI_RL=80; NUCLEI_TIMEOUT=12; KATANA_CT=5; KATANA_C=10; NAABU_RATE=2000; FFUF_THREADS=20
  else
    HTTPX_THREADS=$(( CORES * 30 )); [[ $HTTPX_THREADS -lt 120 ]] && HTTPX_THREADS=120; [[ $HTTPX_THREADS -gt 220 ]] && HTTPX_THREADS=220
    HTTPX_TIMEOUT=7; NUCLEI_C=$(( CORES * 10 )); [[ $NUCLEI_C -lt 50 ]] && NUCLEI_C=50; [[ $NUCLEI_C -gt 100 ]] && NUCLEI_C=100
    NUCLEI_RL=140; NUCLEI_TIMEOUT=10; KATANA_CT=10; KATANA_C=20; NAABU_RATE=5000; FFUF_THREADS=40
  fi
  log "[autotune] CORES=$CORES MEM=${MEM_GB}GB LOSS=${LOSS}% RTT=${AVG_RTT}ms → profile=$PROFILE, nmap_mode=$MODE"
}

ensure_reqs(){ M=(); for t in "${REQ[@]}"; do command -v "$t" &>/dev/null || M+=("$t"); done; (( ${#M[@]} )) && die "Missing: ${M[*]} (run setup)"; }

build_targets(){
  DOMAINS=()
  if (( $# )); then for raw in "$@"; do d="$(to_apex "$raw" | tr -d '\r\n ')"; [[ -n "$d" ]] && DOMAINS+=("$d"); done
  elif [[ -f "$TARGETS_TXT" ]]; then while IFS= read -r raw; do d="$(to_apex "$raw" | tr -d '\r\n ')"; [[ -n "$d" ]] && DOMAINS+=("$d"); done < "$TARGETS_TXT"
  else die "No targets. Use: run example.com  (or create $TARGETS_TXT)"; fi
  declare -A S; DOMAINS_U=(); for d in "${DOMAINS[@]}"; do [[ -z "${S[$d]+x}" ]] && { DOMAINS_U+=("$d"); S[$d]=1; }; done; DOMAINS=("${DOMAINS_U[@]}")
}

run_pipeline(){
  autotune
  { echo "# Tool versions @ $(date -Is)"; for t in "${REQ[@]}" "${OPT[@]}"; do command -v "$t" &>/dev/null && { printf "%-22s " "$t"; "$t" -version 2>/dev/null || "$t" --version 2>/dev/null || "$t" -V 2>/dev/null || echo; }; done; } > "$BASE_DIR/tool_versions.txt"
  SUMMARY="$BASE_DIR/summary_$(date +%Y%m%d_%H%M%S).csv"; echo "domain,live_hosts,nuclei_findings,nmap_open_services,subzy_findings,ffuf_hits,run_dir" > "$SUMMARY"
  for domain in "${DOMAINS[@]}"; do
    ts="$(date +%Y%m%d_%H%M%S)"; RUN_DIR="$BASE_DIR/${domain}_scan_${ts}"; LOGF="$RUN_DIR/live.log"
    mkdir -p "$RUN_DIR"; : > "$LOGF"; log "[*] $domain → $RUN_DIR" | tee -a "$LOGF"
    log "[1/11] subfinder" | tee -a "$LOGF"
    subfinder -d "$domain" -silent | sort -u | tee "$RUN_DIR/subdomains.txt" >/dev/null
    log "[2/11] dnsx" | tee -a "$LOGF"
    dnsx -l "$RUN_DIR/subdomains.txt" -silent -a -aaaa -cname -resp-only -retries 3 -t 120 | sort -u > "$RUN_DIR/resolved.txt"
    dnsx -l "$RUN_DIR/subdomains.txt" -silent -a -aaaa -resp-only | sort -u > "$RUN_DIR/ips.txt" || true
    log "[3/11] httpx" | tee -a "$LOGF"
    httpx -l "$RUN_DIR/resolved.txt" -silent -follow-redirects -title -status-code -tech-detect -json -threads "${HTTPX_THREADS}" -timeout "${HTTPX_TIMEOUT}" | tee "$RUN_DIR/live.jsonl" >/dev/null
    jq -r 'select(.scheme and .input) | .scheme + "://" + .input' "$RUN_DIR/live.jsonl" | sort -u > "$RUN_DIR/live.txt"
    log "[4/11] waybackurls + gau + katana" | tee -a "$LOGF"
    (cat "$RUN_DIR/subdomains.txt" | waybackurls; cat "$RUN_DIR/subdomains.txt" | gau) | sort -u > "$RUN_DIR/urls_history.txt"
    if command -v katana &>/dev/null; then
      log "       katana crawl" | tee -a "$LOGF"
      katana -u "https://$domain" -silent -jc -eff -kf -ef png,jpg,gif,svg,woff,woff2 -d 2 -ps -ct "${KATANA_CT}" -c "${KATANA_C}" | sort -u > "$RUN_DIR/urls_crawl.txt"
    fi
    log "[5/11] gf patterns" | tee -a "$LOGF"
    pushd "$RUN_DIR" >/dev/null; if gf -list >/dev/null 2>&1; then gf -list | while read -r pat; do gf "$pat" < urls_history.txt > "gf_${pat}.txt"; done; fi; popd >/dev/null
    log "[6/11] nuclei (json + text)" | tee -a "$LOGF"
    nuclei -l "$RUN_DIR/live.txt" -severity info,low,medium,high,critical -rl  "${NUCLEI_RL}" -c "${NUCLEI_C}" -timeout "${NUCLEI_TIMEOUT}" -retries 2 -stats -silent -o "$RUN_DIR/nuclei_report.txt"
    nuclei -l "$RUN_DIR/live.txt" -severity info,low,medium,high,critical -rl  "${NUCLEI_RL}" -c "${NUCLEI_C}" -timeout "${NUCLEI_TIMEOUT}" -retries 2 -stats -silent -json -o "$RUN_DIR/nuclei_report.jsonl"
    if command -v naabu &>/dev/null; then
      log "[7/11] naabu (top-100)" | tee -a "$LOGF"
      naabu -l "$RUN_DIR/resolved.txt" -top-ports 100 -rate "${NAABU_RATE}" -o "$RUN_DIR/ports.txt" -silent || true
    fi
    if command -v nmap &>/dev/null; then
      mkdir -p "$RUN_DIR/nmap"; WEB_PORTS="80,443,8080,8443,8000,8008,8888,9000,9001,9002,9443"
      case "$MODE" in
        safe)
          log "[8/11] nmap SAFE" | tee -a "$LOGF"
          [[ -s "$RUN_DIR/ips.txt" ]] && nmap -sV -sC -Pn -T3 -F -iL "$RUN_DIR/ips.txt" -oA "$RUN_DIR/nmap/nmap_fast" || true
          [[ -s "$RUN_DIR/ips.txt" ]] && nmap -sV -Pn -T3 -p "$WEB_PORTS" -iL "$RUN_DIR/ips.txt" --script "http-title,http-headers,http-security-headers,ssl-cert,ssl-enum-ciphers,http-enum" -oA "$RUN_DIR/nmap/nmap_web" || true ;;
        aggr)
          log "[8/11] nmap AGGR" | tee -a "$LOGF"
          if [[ -f "$RUN_DIR/ports.txt" && -s "$RUN_DIR/ports.txt" ]]; then
            awk -F: '{p[$1]=p[$1]","$2} END{for(h in p){gsub(/^,/, "", p[h]); print h" "p[h]}}' "$RUN_DIR/ports.txt" > "$RUN_DIR/nmap/targets_ports.txt" || true
            while read -r host ports; do safe_host="${host//[^A-Za-z0-9_.-]/_}"; nmap -sV -sC -Pn -T3 -p "$ports" "$host" -oA "$RUN_DIR/nmap/nmap_${safe_host}" || true; done < "$RUN_DIR/nmap/targets_ports.txt"
          else
            [[ -s "$RUN_DIR/ips.txt" ]] && nmap -sV -sC -Pn -T3 -F -iL "$RUN_DIR/ips.txt" -oA "$RUN_DIR/nmap/nmap_fast" || true
            [[ -s "$RUN_DIR/ips.txt" ]] && nmap -sV -Pn -T3 -p "$WEB_PORTS" -iL "$RUN_DIR/ips.txt" --script "http-title,http-headers,http-security-headers,ssl-cert,ssl-enum-ciphers,http-enum,http-methods,http-robots.txt" -oA "$RUN_DIR/nmap/nmap_web" || true
          fi ;;
      esac
    fi
    if command -v subzy &>/dev/null; then
      log "[9/11] subzy" | tee -a "$LOGF"
      subzy run --targets "$RUN_DIR/subdomains.txt" --output "$RUN_DIR/subzy_takeover.txt" || true
    fi
    FF_HITS=0
    if command -v ffuf &>/dev/null; then
      log "[10/11] ffuf" | tee -a "$LOGF"
      mkdir -p "$RUN_DIR/ffuf"
      FF_WORDLIST=""
      for wl in /usr/share/seclists/Discovery/Web-Content/common.txt /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt; do [[ -f "$wl" ]] && FF_WORDLIST="$wl" && break; done
      if [[ -z "$FF_WORDLIST" ]]; then FF_WORDLIST="$RUN_DIR/_mini_wordlist.txt"; printf "admin\nlogin\napi\nassets\nuploads\nbackup\nconfig\ndebug\nold\ntest\n" > "$FF_WORDLIST"; fi
      while read -r url; do
        [[ -z "$url" ]] && continue
        host="$(echo "$url" | sed -E 's#^[a-zA-Z]+://##' | cut -d'/' -f1 | cut -d':' -f1)"
        out="$RUN_DIR/ffuf/${host//[^A-Za-z0-9_.-]/_}.json"
        ffuf -u "${url%/}/FUZZ" -w "$FF_WORDLIST" -t  "${FFUF_THREADS}" -mc 200,204,301,302,307,401,403 -of json -o "$out" -timeout 10 -replay-proxy "" 2>/dev/null || true
        hits="$(jq '[.results[]?] | length' "$out" 2>/dev/null || echo 0)"; FF_HITS=$(( FF_HITS + hits ))
      done < "$RUN_DIR/live.txt"
    fi
    if command -v interactsh-client &>/dev/null; then echo "tip: interactsh-client -json -o \"$RUN_DIR/interactsh.jsonl\"" | tee -a "$LOGF"; fi
    livec="0"; nuc="0"; nmapc="0"; subc="0"
    [[ -f "$RUN_DIR/live.txt" ]] && livec="$(wc -l < "$RUN_DIR/live.txt" | tr -d ' ')"
    [[ -f "$RUN_DIR/nuclei_report.txt" ]] && nuc="$(wc -l < "$RUN_DIR/nuclei_report.txt" | tr -d ' ')"
    [[ -d "$RUN_DIR/nmap" ]] && nmapc="$(grep -h ' open ' "$RUN_DIR"/nmap/*.gnmap 2>/dev/null | wc -l | tr -d ' ')"
    [[ -f "$RUN_DIR/subzy_takeover.txt" ]] && subc="$(wc -l < "$RUN_DIR/subzy_takeover.txt" | tr -d ' ')"
    echo "$domain,${livec:-0},${nuc:-0},${nmapc:-0},${subc:-0},${FF_HITS:-0},$RUN_DIR" >> "$SUMMARY"
    (cd "$BASE_DIR" && zip -r "${domain}_report_${ts}.zip" "$(basename "$RUN_DIR")" >/dev/null || true)
    log "✅ $domain done → $RUN_DIR" | tee -a "$LOGF"
  done
  ( cd "$BASE_DIR" && zip -r "ALL_RESULTS_$(date +%Y%m%d_%H%M%S).zip" . -i "*_scan_*" -i "summary_*.csv" -i "tool_versions.txt" >/dev/null || true )
  log "🎉 All done. Summary → $SUMMARY"
  echo "Reminder: Only scan targets you have explicit permission to test."
}

doctor(){
  echo "== DOCTOR =="
  echo "- WSL: $is_wsl"
  echo "- PATH has Go bin: $([[ ":$PATH:" == *":$HOME/go/bin:"* ]] && echo yes || echo no)"
  echo "- BASE_DIR writable: $(test -w "$BASE_DIR" && echo yes || echo no)  ($BASE_DIR)"
  echo "- Network:"
  ping -c 2 -w 5 1.1.1.1 >/dev/null 2>&1 && echo "  ping ok" || echo "  ping fail"
  command -v curl >/dev/null && (curl -Is https://example.com >/dev/null 2>&1 && echo "  https ok" || echo "  https fail") || echo "  curl not found"
  echo "- Tools:"
  for t in "${REQ[@]}" "${OPT[@]}"; do
    if command -v "$t" >/dev/null 2>&1; then printf "  %-20s ok\n" "$t"; else printf "  %-20s missing\n" "$t"; fi
  done
  echo "- Cron:"
  crontab -l 2>/dev/null | sed 's/^/  /' || echo "  (no crontab)"
}

highlights(){
  local d="${1:-}"
  local LATEST
  if [[ -n "$d" ]]; then
    LATEST=$(ls -d "$BASE_DIR"/"${d}"_scan_* 2>/dev/null | sort | tail -n1 || true)
  else
    LATEST=$(ls -d "$BASE_DIR"/*_scan_* 2>/dev/null | sort | tail -n1 || true)
  fi
  [[ -z "$LATEST" ]] && { echo "No scan dir found."; return 1; }
  local OUT="$LATEST/highlights.txt"
  {
    echo "# Highlights for $(basename "$LATEST")"
    echo "Run dir: $LATEST"
    echo
    if [[ -s "$LATEST/nuclei_report.jsonl" ]]; then
      echo "## Nuclei (high/critical):"
      jq -r 'select(.info.severity=="high" or .info.severity=="critical") | [.info.severity, .templateID, .host, .matched-at] | @tsv' "$LATEST/nuclei_report.jsonl" | sed 's/^/ - /'
      echo
    elif [[ -s "$LATEST/nuclei_report.txt" ]]; then
      echo "## Nuclei (text):"
      sed 's/^/ - /' "$LATEST/nuclei_report.txt" | head -n 200
      echo
    fi
    if compgen -G "$LATEST/nmap/*.gnmap" > /dev/null; then
      echo "## Nmap open services (top):"
      grep -h ' open ' "$LATEST"/nmap/*.gnmap | head -n 100 | sed 's/^/ - /'
      echo
    fi
    if [[ -s "$LATEST/subzy_takeover.txt" ]]; then
      echo "## Possible takeover:"
      sed 's/^/ - /' "$LATEST/subzy_takeover.txt"
      echo
    fi
    if [[ -d "$LATEST/ffuf" ]]; then
      echo "## FFUF hits (count per host):"
      for f in "$LATEST"/ffuf/*.json; do [[ -f "$f" ]] || continue; c=$(jq '[.results[]?] | length' "$f" 2>/dev/null || echo 0); echo " - $(basename "$f"): $c"; done
      echo
    fi
    echo "## Live hosts count:"; [[ -f "$LATEST/live.txt" ]] && wc -l "$LATEST/live.txt" || echo " - (no live.txt)"
  } > "$OUT"
  echo "✅ Highlights → $OUT"
}

schedule_job(){
  build_targets "$@"
  printf "%s\n" "${DOMAINS[@]}" > "$TARGETS_TXT"
  local RUNNER="$WORKDIR/bughunt_runner.sh"
  echo -e "#!/usr/bin/env bash\nexec \"$0\" run" > "$RUNNER"
  chmod +x "$RUNNER"
  ( crontab -l 2>/dev/null | grep -v "$RUNNER" ; echo "0 1 * * * $RUNNER >> $CRON_LOG 2>&1" ) | crontab -
  command -v service &>/dev/null && { sudo service cron start || true; sudo systemctl enable cron 2>/dev/null || true; }
  log "✅ Scheduled daily 01:00 for: ${DOMAINS[*]} (targets in $TARGETS_TXT)"
}

unschedule_job(){
  local RUNNER="$WORKDIR/bughunt_runner.sh"; local TMP
  TMP="$(mktemp)"; crontab -l 2>/dev/null | grep -v "$RUNNER" > "$TMP" || true; crontab "$TMP" || true; rm -f "$TMP" "$RUNNER"
  log "🗑️  Removed schedule (if existed)."
}

show_status(){
  echo "== Versions =="
  for t in "${REQ[@]}" "${OPT[@]}"; do if command -v "$t" &>/dev/null; then printf "%-20s " "$t"; "$t" -version 2>/dev/null || "$t" --version 2>/dev/null || "$t" -V 2>/dev/null || echo; else printf "%-20s not found\n" "$t"; fi; done
  echo; echo "== Cron =="; crontab -l 2>/dev/null | sed 's/^/  /' || echo "  (no crontab)"
  echo; echo "Targets file: $TARGETS_TXT"; [[ -f "$TARGETS_TXT" ]] && nl -ba "$TARGETS_TXT" | sed 's/^/  /'
  echo; echo "Output dir: $BASE_DIR"
}

case "$ACTION" in
  setup)      install_tools ;;
  run)        ensure_reqs; build_targets "$@"; run_pipeline ;;
  schedule)   install_tools; schedule_job "$@" ;;
  unschedule) unschedule_job ;;
  status)     show_status ;;
  doctor)     doctor ;;
  highlights) highlights "$@" ;;
esac
