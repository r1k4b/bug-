#!/usr/bin/env bash
# recon_telegram.sh
# Pro-level Recon Automation with Telegram Live Reporting
# Usage: BOT_TOKEN=xxxx CHAT_ID=yyyy ./recon_telegram.sh example.com

set -e

domain="$1"
if [[ -z "$domain" ]]; then
  echo "Usage: BOT_TOKEN=xxxx CHAT_ID=yyyy $0 example.com"
  exit 1
fi

BOT_TOKEN="${BOT_TOKEN}"
CHAT_ID="${CHAT_ID}"

if [[ -z "$BOT_TOKEN" || -z "$CHAT_ID" ]]; then
  echo "Error: BOT_TOKEN and CHAT_ID env vars must be set."
  exit 1
fi

OUTDIR="results_${domain}_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUTDIR"

tg_api="https://api.telegram.org/bot${BOT_TOKEN}"

tg_msg() {
  local MSG="$1"
  curl -s -X POST "${tg_api}/sendMessage"        -d chat_id="${CHAT_ID}"        --data-urlencode "text=${MSG}" > /dev/null
}

tg_msg "🚀 *ReconBot* started recon for *${domain}*"

# 1. Subdomain enumeration
tg_msg "🔍 Running subfinder..."
subfinder -silent -d "$domain" -o "$OUTDIR/subs_raw.txt"
sort -u "$OUTDIR/subs_raw.txt" > "$OUTDIR/subs.txt"
subs_ct=$(wc -l < "$OUTDIR/subs.txt")
tg_msg "✅ subfinder done • *${subs_ct}* subdomains."

# 2. DNS resolving
tg_msg "🌐 Resolving with dnsx..."
dnsx -silent -l "$OUTDIR/subs.txt" -o "$OUTDIR/resolved.txt"
live_ct=$(wc -l < "$OUTDIR/resolved.txt")
tg_msg "✅ dnsx done • *${live_ct}* live hosts."

# 3. URL collection
tg_msg "📜 Collecting URLs (waybackurls + gau)..."
cat "$OUTDIR/resolved.txt" | waybackurls >> "$OUTDIR/urls_raw.txt"
cat "$OUTDIR/resolved.txt" | gau --subs >> "$OUTDIR/urls_raw.txt"
sort -u "$OUTDIR/urls_raw.txt" > "$OUTDIR/urls.txt"
url_ct=$(wc -l < "$OUTDIR/urls.txt")
tg_msg "✅ Collected *${url_ct}* URLs."

# 4. GF filtering
tg_msg "🧹 Filtering params with gf..."
cat "$OUTDIR/urls.txt" | gf xss > "$OUTDIR/xss.txt"
cat "$OUTDIR/urls.txt" | gf sqli > "$OUTDIR/sqli.txt"
cat "$OUTDIR/urls.txt" | grep '\.js$' > "$OUTDIR/js.txt"
xss_ct=$(wc -l < "$OUTDIR/xss.txt")
sqli_ct=$(wc -l < "$OUTDIR/sqli.txt")
tg_msg "✅ Param filter: XSS=${xss_ct}, SQLi=${sqli_ct}"

# 5. Nuclei scans
tg_msg "🚀 Nuclei (exposures)..."
nuclei -silent -t exposures/ -l "$OUTDIR/resolved.txt" -o "$OUTDIR/exposures.txt"
exp_ct=$(wc -l < "$OUTDIR/exposures.txt")
tg_msg "📂 exposures done: ${exp_ct}"

tg_msg "🔑 Nuclei (default-logins)..."
nuclei -silent -t default-logins/ -l "$OUTDIR/resolved.txt" -o "$OUTDIR/logins.txt"
log_ct=$(wc -l < "$OUTDIR/logins.txt")
tg_msg "🛂 default-logins done: ${log_ct}"

tg_msg "💥 Nuclei (vulnerabilities) on XSS params..."
if [[ "$xss_ct" -gt 0 ]]; then
  nuclei -silent -t vulnerabilities/ -l "$OUTDIR/xss.txt" -o "$OUTDIR/vuln_xss.txt"
  vul_ct=$(wc -l < "$OUTDIR/vuln_xss.txt")
else
  vul_ct=0; touch "$OUTDIR/vuln_xss.txt"
fi
tg_msg "🔬 vuln scan done: ${vul_ct}"

# 6. JS leak grep
tg_msg "🔎 Grepping JS for tokens..."
token_file="$OUTDIR/js_leaks.txt"
while read -r url; do
  curl -s "$url" | grep -Eoi '(api[_-]?key|secret|token)["=: ]+[A-Za-z0-9\-_]{8,}' >> "$token_file" || true
done < "$OUTDIR/js.txt"
tok_ct=$(wc -l < "$token_file" 2>/dev/null || echo 0)
tg_msg "🔐 JS token scan: ${tok_ct} potential hits."

# 7. Summary + zip
summary="🏁 *Recon finished for ${domain}*
Subdomains: ${subs_ct}
Live: ${live_ct}
URLs: ${url_ct}
Exposures: ${exp_ct}
Default-Logins: ${log_ct}
Vuln(XSS): ${vul_ct}
JS Tokens: ${tok_ct}"

zip_file="${OUTDIR}.zip"
zip -qr "$zip_file" "$OUTDIR"
tg_msg "$summary"
curl -s -F document=@"$zip_file" -F chat_id="${CHAT_ID}" "${tg_api}/sendDocument" > /dev/null
tg_msg "🎉 ReconBot done. Happy hunting!"
