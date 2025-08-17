#!/usr/bin/env bash
# bug1.sh – Full recon + vuln scan + performance tuned
# Added optional Cookie header support via -H "Cookie: ..." for httpx and nuclei

set -Eeuo pipefail
shopt -s inherit_errexit

[[ $# -lt 1 || "$1" =~ ^(-h|--help)$ ]] && { echo "Usage: $0 <domain>"; exit 1; }
domain="$1"

read -rp "🔸 Pendrive path (e.g. /mnt/e/bughunt): " base_dir
[[ -z "$base_dir" ]] && { echo "✖️  Path cannot be empty"; exit 1; }
read -rp "🍪 Cookie header (optional, e.g. 'session=abc; other=xyz'): " cookie
if [[ -n "$cookie" ]]; then
  header_arg_httpx=(-H "Cookie: $cookie")
  header_arg_nuclei=(-H "Cookie: $cookie")
  log "[auth] Cookie provided (hidden)"
else
  header_arg_httpx=()
  header_arg_nuclei=()
fi


scan_dir="$base_dir/${domain}_scan"
mkdir -p "$scan_dir" || { echo "✖️  Cannot create $scan_dir"; exit 1; }
live_log="$scan_dir/live_results.txt"; : >"$live_log"

log(){ printf '%(%H:%M:%S)T %s\n' -1 "$*"; }

#──────── টুল চেক ────────#
required=(subfinder httpx waybackurls gf nuclei curl subzy zip parallel)
for t in "${required[@]}"; do command -v "$t" &>/dev/null || \
  { echo "❌ Install $t first"; exit 1; }; done

log "[*] Output → $scan_dir"
log "[*] Live log → $live_log"

#──────── [1] Subdomain Enumeration ────────#
log "[1/7] subfinder..."
subfinder -d "$domain" -silent \
  | tee "$scan_dir/subdomains.txt" \
  | sed 's/^/[subfinder] /' >> "$live_log"

#──────── [2] Live Host Detection ────────#
log "[2/7] httpx live check..."
httpx -l "$scan_dir/subdomains.txt" ${header_arg_httpx[@]} -silent -threads 50 -timeout 5 \
  | tee "$scan_dir/live_hosts.txt" \
  | sed 's/^/[httpx] /' >> "$live_log"
log "    $(wc -l <"$scan_dir/live_hosts.txt") live hosts."

#──────── [3] Wayback URLs + JS filter ────────#
log "[3/7] waybackurls..."
waybackurls <"$scan_dir/subdomains.txt" > "$scan_dir/wayback_urls.txt"
grep -Ei '\.js(\?|$)' "$scan_dir/wayback_urls.txt" | sort -u > "$scan_dir/js_urls.txt"

#──────── [4] GF patterns (parallel) ────────#
log "[4/7] GF patterns..."
cd "$scan_dir"
gf -list | parallel 'gf {} < wayback_urls.txt > {}.txt'
cd - >/dev/null

#──────── [5] nuclei vuln scan (all severity) ────────#
log "[5/7] nuclei (info to critical, -c 60)..."
stdbuf -oL nuclei -l "$scan_dir/live_hosts.txt" \
       -severity info,low,medium,high,critical \
       -c 60 \
       ${header_arg_nuclei[@]} \
       -o "$scan_dir/nuclei_report.txt" -silent \
| stdbuf -oL sed 's/^/[nuclei] /' | tee -a "$live_log"

#──────── [6] Subdomain Takeover check ────────#
log "[6/7] subzy takeover scan..."
subzy run --targets "$scan_dir/subdomains.txt" --output "$scan_dir/subzy_takeover.txt"

#──────── [7] Auto Zipping ────────#
log "[7/7] Zipping report..."
zip -r "$base_dir/${domain}_report.zip" "$scan_dir" >/dev/null

#──────── Summary ────────#
log "✅ All tasks completed!"
log "📁 Folder: $scan_dir"
log "📄 Live log: tail -f $live_log"
log "📦 Zipped Report: $base_dir/${domain}_report.zip"