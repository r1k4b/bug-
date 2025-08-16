#!/usr/bin/env bash
# bug1_allinone.sh — simple, one‑command, full recon automation (AUTHORIZED targets only)
# Usage:
#   chmod +x bug1_allinone.sh
#   ./bug1_allinone.sh install
#   ./bug1_allinone.sh example.com [more domains or URLs]
set -Eeuo pipefail

say(){ printf '%s\n' "$*"; }
log(){ printf '%(%Y-%m-%d %H:%M:%S)T %s\n' -1 "$*"; }
to_host(){ echo "$1" | sed -E 's#^[a-zA-Z]+://##' | cut -d'/' -f1 | cut -d':' -f1; }
to_apex(){ local h; h="$(to_host "$1")"; local d; d="$(grep -o "\." <<< "$h" | wc -l || echo 0)"; (( d >= 2 )) && echo "${h#*.}" || echo "$h"; }

# Output base (on WSL -> Desktop\bughunt_out, otherwise ./bughunt_out)
is_wsl=false; grep -qi microsoft /proc/version 2>/dev/null && is_wsl=true
if $is_wsl && [[ -d /mnt/c/Users ]]; then
  BASE_DIR=""
  for u in "$(/bin/ls -1 /mnt/c/Users 2>/dev/null)"; do
    if [[ -d "/mnt/c/Users/$u/Desktop" ]]; then BASE_DIR="/mnt/c/Users/$u/Desktop/bughunt_out"; break; fi
  done
  [[ -z "$BASE_DIR" ]] && BASE_DIR="$PWD/bughunt_out"
else
  BASE_DIR="$PWD/bughunt_out"
fi
mkdir -p "$BASE_DIR"

install_tools(){
  say "Installing (apt + Go + pip) ..."
  command -v apt >/dev/null 2>&1 || { say "✖ Requires Ubuntu/WSL (apt)."; exit 1; }
  sudo apt update -y || true
  sudo apt install -y git curl jq zip build-essential golang-go seclists nmap parallel python3 python3-pip whatweb sslscan masscan || true

  export PATH="$PATH:$HOME/go/bin"
  export GOPROXY="${GOPROXY:-https://proxy.golang.org,direct}"

  # Go tools
  go install -v github.com/owasp-amass/amass/v4/...@latest || true
  go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest || true
  go install -v github.com/tomnomnom/assetfinder@latest || true
  go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest || true
  go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest || true
  go install -v github.com/projectdiscovery/katana/cmd/katana@latest || true
  go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest || true
  go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest || true
  go install -v github.com/tomnomnom/waybackurls@latest || true
  go install -v github.com/lc/gau/v2/cmd/gau@latest || true
  go install -v github.com/tomnomnom/gf@latest || true
  go install -v github.com/tomnomnom/unfurl@latest || true
  go install -v github.com/ffuf/ffuf@latest || true
  go install -v github.com/sensepost/gowitness@latest || true
  go install -v github.com/LukaSikic/subzy@latest || true
  go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest || true

  # Python tools
  python3 -m pip install --upgrade pip || true
  python3 -m pip install dnsgen arjun wafw00f linkfinder mmh3 requests tqdm dirsearch || true

  # testssl.sh + gf patterns
  mkdir -p "$HOME/tools"
  [[ -d "$HOME/tools/testssl.sh" ]] || git clone --depth=1 https://github.com/drwetter/testssl.sh.git "$HOME/tools/testssl.sh" || true
  mkdir -p "$HOME/.gf"
  if [[ ! -d "$HOME/.gf/examples" ]]; then
    tmp="$HOME/.gf-tmp-$$"; git clone --depth=1 https://github.com/tomnomnom/gf "$tmp" 2>/dev/null || true
    cp -r "$tmp/examples/"* "$HOME/.gf/" 2>/dev/null || true
    rm -rf "$tmp" || true
  fi
  nuclei -update-templates || true
  say "✔ Install complete. If 'command not found': export PATH=\"$PATH:$HOME/go/bin\""
}

ensure_tools(){
  local need=(amass subfinder assetfinder dnsx httpx katana waybackurls gau gf unfurl wafw00f nuclei jq zip naabu masscan nmap sslscan whatweb subzy ffuf gowitness parallel python3)
  local miss=(); for t in "${need[@]}"; do command -v "$t" >/dev/null 2>&1 || miss+=("$t"); done
  if (( ${#miss[@]} )); then
    say "Missing tools: ${miss[*]} → auto-installing ..."
    install_tools
  fi
}

autotune(){
  CORES="$(nproc 2>/dev/null || echo 2)"
  HTTPX_THREADS=$(( CORES * 25 )); [[ $HTTPX_THREADS -lt 100 ]] && HTTPX_THREADS=100; [[ $HTTPX_THREADS -gt 220 ]] && HTTPX_THREADS=220
  NUCLEI_C=$(( CORES * 10 ));     [[ $NUCLEI_C -lt 50 ]] && NUCLEI_C=50;       [[ $NUCLEI_C -gt 120 ]] && NUCLEI_C=120
  KATANA_CT=10; KATANA_C=20
  NAABU_RATE=$(( CORES * 500 )); [[ $NAABU_RATE -lt 3000 ]] && NAABU_RATE=3000; [[ $NAABU_RATE -gt 8000 ]] && NAABU_RATE=8000
  MASSCAN_RATE=$(( CORES * 600 )); [[ $MASSCAN_RATE -lt 2000 ]] && MASSCAN_RATE=2000; [[ $MASSCAN_RATE -gt 10000 ]] && MASSCAN_RATE=10000
  FFUF_THREADS=50
  GOWIT_THREADS=$(( CORES * 2 )); [[ $GOWIT_THREADS -lt 6 ]] && GOWIT_THREADS=6; [[ $GOWIT_THREADS -gt 24 ]] && GOWIT_THREADS=24
  log "[autotune] cores=$CORES httpx=$HTTPX_THREADS nuclei=$NUCLEI_C naabu=$NAABU_RATE masscan=$MASSCAN_RATE ffuf=$FFUF_THREADS gowitness=$GOWIT_THREADS"
}

run_one(){
  local d_in="$1"
  local domain="$(to_apex "$d_in")"
  local ts="$(date +%Y%m%d_%H%M%S)"
  local out="$BASE_DIR/${domain}_scan_${ts}"
  mkdir -p "$out"
  local logf="$out/live.log"; : > "$logf"

  say "▶ Target: $d_in (apex: $domain)"
  say "→ Output: $out"
  say "→ Live:   $logf"

  # 1) Subdomains
  say "[1/16] subfinder + assetfinder + amass" | tee -a "$logf"
  ( subfinder -d "$domain" -silent ; assetfinder --subs-only "$domain" 2>/dev/null || true ; amass enum -passive -d "$domain" 2>/dev/null || true ) \
    | sort -u | tee "$out/subdomains_raw.txt" >/dev/null

  # 2) Permutations → dnsgen
  say "[2/16] dnsgen permutations" | tee -a "$logf"
  if [[ -s "$out/subdomains_raw.txt" ]]; then
    python3 -m dnsgen "$out/subdomains_raw.txt" --bitsquatting --hyphenation --insertion --omission --repetition --replacement --transposition \
      | sort -u > "$out/subdomains_perms.txt" || true
    cat "$out/subdomains_raw.txt" "$out/subdomains_perms.txt" | sort -u > "$out/subdomains.txt"
  else
    cp "$out/subdomains_raw.txt" "$out/subdomains.txt" 2>/dev/null || :
  fi

  # 3) Resolve + IPs
  say "[3/16] dnsx resolve (A/AAAA/CNAME + IPs)" | tee -a "$logf"
  dnsx -l "$out/subdomains.txt" -silent -a -aaaa -cname -resp-only -retries 2 -t 120 | sort -u > "$out/resolved.txt"
  dnsx -l "$out/subdomains.txt" -silent -a -aaaa -resp-only | sort -u > "$out/ips.txt" || true

  # 4) Live hosts
  say "[4/16] httpx live (threads=$HTTPX_THREADS)" | tee -a "$logf"
  httpx -l "$out/resolved.txt" -silent -follow-redirects -status-code -title -tech-detect -json -threads "$HTTPX_THREADS" -timeout 8 \
    | tee "$out/live.jsonl" >/dev/null
  jq -r 'select(.scheme and .input) | .scheme + "://" + .input' "$out/live.jsonl" | sort -u > "$out/live.txt"

  # 5) URLs (archive+crawl)
  say "[5/16] waybackurls + gau + katana" | tee -a "$logf"
  (cat "$out/subdomains.txt" | waybackurls; cat "$out/subdomains.txt" | gau) | sort -u > "$out/urls_history.txt"
  katana -u "https://$domain" -silent -jc -eff -kf -ef png,jpg,gif,svg,woff,woff2 -d 2 -ps -ct "$KATANA_CT" -c "$KATANA_C" \
    | sort -u > "$out/urls_crawl.txt" || true
  cat "$out/urls_history.txt" "$out/urls_crawl.txt" 2>/dev/null | sort -u > "$out/urls_all.txt"

  # 6) Params + patterns
  say "[6/16] unfurl (params) + gf + linkfinder(JS)" | tee -a "$logf"
  : > "$out/params.txt"; : > "$out/param_values.txt"
  if [[ -s "$out/urls_all.txt" ]]; then
    unfurl keys < "$out/urls_all.txt" | sort -u > "$out/params.txt" || true
    unfurl values < "$out/urls_all.txt" | sort -u > "$out/param_values.txt" || true
  fi
  grep -Ei '\.js(\?|$)' "$out/urls_all.txt" 2>/dev/null | sort -u > "$out/js_urls.txt" || true
  : > "$out/js_endpoints.txt"
  if [[ -s "$out/js_urls.txt" ]]; then
    cat "$out/js_urls.txt" | parallel -j 6 'python3 -m linkfinder -i {} -o cli 2>/dev/null' | sort -u > "$out/js_endpoints.txt" || true
  fi
  if gf -list >/dev/null 2>&1; then
    pushd "$out" >/dev/null
    gf -list | parallel 'gf {} < urls_all.txt > gf_{}.txt' || true
    popd >/dev/null
  fi

  # 7) Favicon hash + 8) WAF
  say "[7/16] mmh3 favicon hash  |  [8/16] wafw00f" | tee -a "$logf"
  : > "$out/favicon_hash.txt"; : > "$out/waf.txt"
  head -n 500 "$out/live.txt" 2>/dev/null | parallel -j 10 'python3 - <<PY
import sys,requests,mmh3,base64,urllib3
urllib3.disable_warnings()
u=sys.argv[1].rstrip("/")
try:
  r=requests.get(u+"/favicon.ico",verify=False,timeout=8)
  if r.status_code==200 and r.content:
    h=mmh3.hash(base64.b64encode(r.content).decode()); print(u+"\\t"+str(h))
except Exception: pass
PY' {} >> "$out/favicon_hash.txt"
  { echo "$domain"; head -n 50 "$out/subdomains.txt" 2>/dev/null; } | sort -u \
    | parallel -j 8 'wafw00f -a {} 2>/dev/null | head -n 3 | tr -d "\r" | sed "s/^/[waf] /"' \
    | tee "$out/waf.txt" >/dev/null

  # 9) Ports — naabu + masscan
  say "[9/16] naabu (top-100, rate=$NAABU_RATE) + masscan(1-1000, rate=$MASSCAN_RATE)" | tee -a "$logf"
  if [[ -s "$out/resolved.txt" ]]; then
    naabu -l "$out/resolved.txt" -top-ports 100 -rate "$NAABU_RATE" -o "$out/ports_naabu.txt" -silent || true
  fi
  if [[ -s "$out/ips.txt" ]]; then
    sudo -n true 2>/dev/null && MSUDO="sudo" || MSUDO=""
    $MSUDO masscan -p1-1000 --rate "$MASSCAN_RATE" -iL "$out/ips.txt" -oL "$out/masscan.txt" 2>/dev/null || true
  fi

  # 10) Nmap
  say "[10/16] nmap (service + web scripts)" | tee -a "$logf"
  if [[ -s "$out/ips.txt" ]]; then
    mkdir -p "$out/nmap"
    nmap -sV -sC -Pn -T3 -F -iL "$out/ips.txt" -oA "$out/nmap/nmap_fast" || true
    WEB_PORTS="80,443,8080,8443,8000,8008,8888,9000,9002,9443"
    nmap -sV -Pn -T3 -p "$WEB_PORTS" -iL "$out/ips.txt" \
      --script "http-title,http-headers,http-enum,ssl-cert,ssl-enum-ciphers,http-security-headers" -oA "$out/nmap/nmap_web" || true
  fi

  # 11) TLS (apex)
  say "[11/16] sslscan + testssl.sh" | tee -a "$logf"
  mkdir -p "$out/tls"
  (sslscan "https://$domain" || true) | tee "$out/tls/sslscan.txt" >/dev/null || true
  "$HOME/tools/testssl.sh/testssl.sh" --fast --parallel "https://$domain" | tee "$out/tls/testssl.txt" >/dev/null || true

  # 12) whatweb
  say "[12/16] whatweb fingerprint" | tee -a "$logf"
  whatweb -i "$out/live.txt" --log-brief "$out/whatweb.txt" 2>/dev/null || true

  # 13) Screenshots
  say "[13/16] gowitness screenshots (threads=$GOWIT_THREADS)" | tee -a "$logf"
  mkdir -p "$out/screens"
  if [[ -s "$out/live.txt" ]]; then
    gowitness file -f "$out/live.txt" -P "$out/screens" --timeout 12 --threads "$GOWIT_THREADS" || true
  fi

  # 14) Takeover
  say "[14/16] subzy takeover" | tee -a "$logf"
  subzy run --targets "$out/subdomains.txt" --output "$out/subzy_takeover.txt" || true

  # 15) Content
  say "[15/16] ffuf + dirsearch" | tee -a "$logf"
  mkdir -p "$out/ffuf"
  local FF_WORDLIST=""
  for wl in /usr/share/seclists/Discovery/Web-Content/common.txt /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt; do
    [[ -f "$wl" ]] && FF_WORDLIST="$wl" && break
  done
  if [[ -z "$FF_WORDLIST" ]]; then
    FF_WORDLIST="$out/_mini_wordlist.txt"
    printf "admin\nlogin\napi\nassets\nuploads\nbackup\nconfig\ndebug\nold\ntest\n" > "$FF_WORDLIST"
  fi
  local FF_HITS=0
  if [[ -s "$out/live.txt" ]]; then
    while read -r url; do
      [[ -z "$url" ]] && continue
      host="$(to_host "$url")"
      ffjson="$out/ffuf/${host//[^A-Za-z0-9_.-]/_}.json"
      ffuf -u "${url%/}/FUZZ" -w "$FF_WORDLIST" -t "$FFUF_THREADS" -mc 200,204,301,302,307,401,403 -of json -o "$ffjson" -timeout 10 -replay-proxy "" 2>/dev/null || true
      hits="$(jq '[.results[]?] | length' "$ffjson" 2>/dev/null || echo 0)"
      FF_HITS=$(( FF_HITS + hits ))
    done < "$out/live.txt"
    python3 -m dirsearch -l "$out/live.txt" -w "$FF_WORDLIST" -e php,aspx,js,zip,txt -o "$out/dirsearch.txt" --timeout=10 --threads=40 --quiet || true
  fi

  # 16) nuclei (last)
  say "[16/16] nuclei templates (-c $NUCLEI_C)" | tee -a "$logf"
  if [[ -s "$out/live.txt" ]]; then
    nuclei -l "$out/live.txt" -severity info,low,medium,high,critical -c "$NUCLEI_C" -timeout 10 -retries 2 -silent -o "$out/nuclei_report.txt" \
      | sed 's/^/[nuclei] /' | tee -a "$logf" >/dev/null
    nuclei -l "$out/live.txt" -severity info,low,medium,high,critical -c "$NUCLEI_C" -timeout 10 -retries 2 -silent -json -o "$out/nuclei_report.jsonl" || true
  else
    : > "$out/nuclei_report.txt"
  fi

  # Summary + ZIP
  SUBC="$(wc -l < "$out/subdomains.txt" 2>/dev/null || echo 0)"
  RESC="$(wc -l < "$out/resolved.txt" 2>/dev/null || echo 0)"
  LIVEC="$(wc -l < "$out/live.txt" 2>/dev/null || echo 0)"
  NUCC="$(wc -l < "$out/nuclei_report.txt" 2>/dev/null || echo 0)"
  NMAPC="$(grep -h ' open ' "$out"/nmap/*.gnmap 2>/dev/null | wc -l | tr -d ' ' || echo 0)"
  SUBC_TAKE="$(wc -l < "$out/subzy_takeover.txt" 2>/dev/null || echo 0)"
  echo "domain,subdomains,resolved,live_hosts,nuclei_lines,nmap_open,subzy_findings,ffuf_hits,run_dir" > "$out/summary.csv"
  echo "$domain,$SUBC,$RESC,$LIVEC,$NUCC,$NMAPC,$SUBC_TAKE,$FF_HITS,$out" >> "$out/summary.csv"

  ( cd "$BASE_DIR" && zip -r "${domain}_report_${ts}.zip" "$(basename "$out")" >/dev/null ) || true
  say "✔ Done: $d_in"
  say "ZIP: $BASE_DIR/${domain}_report_${ts}.zip"
  say "-----------------------------------------"
}

main(){
  if [[ $# -eq 0 ]]; then
    say "Usage: $0 install | <domain> [more domains]"; exit 0
  fi
  if [[ "$1" == "install" ]]; then install_tools; exit 0; fi
  export PATH="$PATH:$HOME/go/bin"
  ensure_tools
  autotune
  for d in "$@"; do run_one "$d"; done
  say "All reports saved in: $BASE_DIR"
}
main "$@"
