#!/usr/bin/env bash
# recon_local_v2.sh
# Recon Automation WITH httpx tech fingerprint
# Usage: ./recon_local_v2.sh example.com

set -e
domain="$1"
if [[ -z "$domain" ]]; then
  echo "Usage: $0 example.com"
  exit 1
fi

timestamp=$(date +%Y%m%d_%H%M%S)
OUTDIR="results_${domain}_${timestamp}"
mkdir -p "$OUTDIR"

echo "[*] Recon for $domain | Output: $OUTDIR"

# 1. Subdomain enum
echo "[+] subfinder ..."
subfinder -silent -d "$domain" -o "$OUTDIR/subs_raw.txt"
sort -u "$OUTDIR/subs_raw.txt" > "$OUTDIR/subs.txt"
subs_ct=$(wc -l < "$OUTDIR/subs.txt")
echo "    Subdomains: $subs_ct"

# 2. Resolve
echo "[+] dnsx ..."
dnsx -silent -l "$OUTDIR/subs.txt" -o "$OUTDIR/resolved.txt"
live_ct=$(wc -l < "$OUTDIR/resolved.txt")
echo "    Live hosts: $live_ct"

# 3. httpx tech fingerprint
echo "[+] httpx tech-detect ..."
httpx -silent -l "$OUTDIR/resolved.txt" -tech-detect -title -status-code -o "$OUTDIR/tech.txt"
tech_ct=$(wc -l < "$OUTDIR/tech.txt")
echo "    httpx entries: $tech_ct"

# 4. URL collection
echo "[+] URLs (waybackurls + gau) ..."
cat "$OUTDIR/resolved.txt" | waybackurls >> "$OUTDIR/urls_raw.txt"
cat "$OUTDIR/resolved.txt" | gau --subs >> "$OUTDIR/urls_raw.txt"
sort -u "$OUTDIR/urls_raw.txt" > "$OUTDIR/urls.txt"
url_ct=$(wc -l < "$OUTDIR/urls.txt")
echo "    URLs: $url_ct"

# 5. GF filter
echo "[+] gf filtering ..."
cat "$OUTDIR/urls.txt" | gf xss > "$OUTDIR/xss.txt"
cat "$OUTDIR/urls.txt" | gf sqli > "$OUTDIR/sqli.txt"
cat "$OUTDIR/urls.txt" | grep '\.js$' > "$OUTDIR/js.txt"
xss_ct=$(wc -l < "$OUTDIR/xss.txt")
sqli_ct=$(wc -l < "$OUTDIR/sqli.txt")
echo "    XSS: $xss_ct | SQLi: $sqli_ct"

# 6. nuclei scans
echo "[+] nuclei scans ..."
nuclei -silent -t exposures/ -l "$OUTDIR/resolved.txt" -o "$OUTDIR/exposures.txt"
exp_ct=$(wc -l < "$OUTDIR/exposures.txt")
nuclei -silent -t default-logins/ -l "$OUTDIR/resolved.txt" -o "$OUTDIR/logins.txt"
log_ct=$(wc -l < "$OUTDIR/logins.txt")
if [[ "$xss_ct" -gt 0 ]]; then
  nuclei -silent -t vulnerabilities/ -l "$OUTDIR/xss.txt" -o "$OUTDIR/vuln_xss.txt"
  vul_ct=$(wc -l < "$OUTDIR/vuln_xss.txt")
else
  vul_ct=0; touch "$OUTDIR/vuln_xss.txt"
fi
echo "    Exposures: $exp_ct | DefaultLogins: $log_ct | XSS Vulns: $vul_ct"

# 7. JS token grep
echo "[+] JS token grep ..."
token_file="$OUTDIR/js_leaks.txt"
while read -r url; do
  curl -s "$url" | grep -Eoi '(api[_-]?key|secret|token)["=: ]+[A-Za-z0-9\-_]{8,}' >> "$token_file" || true
done < "$OUTDIR/js.txt"
tok_ct=$(wc -l < "$token_file" 2>/dev/null || echo 0)
echo "    JS token hits: $tok_ct"

# 8. summary
summary="$OUTDIR/summary.txt"
cat <<EOF > "$summary"
Recon Summary for $domain
Timestamp        : $(date)
----------------------------------------
Subdomains        : $subs_ct
Live Hosts        : $live_ct
Tech Fingerprint  : $tech_ct
Collected URLs    : $url_ct
Exposures         : $exp_ct
Default Logins    : $log_ct
XSS Vulns         : $vul_ct
JS Token Hits     : $tok_ct
Output Directory  : $OUTDIR
EOF
echo "[*] Recon finished! Summary: $summary"
