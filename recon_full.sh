#!/usr/bin/env bash
# recon_full.sh
# Comprehensive Recon Automation (no vuln scans)
# Collects: subdomains, live hosts, ports, tech, URLs, JS, param lists
#
# Usage: ./recon_full.sh example.com
# Outputs saved under results_<domain>_<timestamp>/

set -euo pipefail

domain="$1"
if [[ -z "$domain" ]]; then
  echo "Usage: $0 example.com"
  exit 1
fi

timestamp=$(date +%Y%m%d_%H%M%S)
OUTDIR="results_${domain}_${timestamp}"
mkdir -p "$OUTDIR"

echo "=============================================="
echo "[*] FULL RECON for ${domain}"
echo "[*] Output dir: ${OUTDIR}"
echo "=============================================="

# ---------- 1. Subdomain Enumeration ----------
echo "[+] Step 1: Subdomain enum (subfinder, assetfinder)..."
subfinder -silent -d "$domain" -o "$OUTDIR/subs_subfinder.txt"
assetfinder --subs-only "$domain" > "$OUTDIR/subs_assetfinder.txt" 2>/dev/null || true
cat "$OUTDIR"/subs_*.txt | sort -u > "$OUTDIR/subdomains.txt"
subs_ct=$(wc -l < "$OUTDIR/subdomains.txt")
echo "    Total unique subdomains: ${subs_ct}"

# ---------- 2. Resolve & Live Host Check ----------
echo "[+] Step 2: DNS resolving (dnsx)..."
dnsx -silent -l "$OUTDIR/subdomains.txt" -o "$OUTDIR/resolved.txt"
live_ct=$(wc -l < "$OUTDIR/resolved.txt")
echo "    Live hosts: ${live_ct}"

# ---------- 3. Port Scan ----------
echo "[+] Step 3: Fast port scan (naabu)..."
naabu -silent -p - -l "$OUTDIR/resolved.txt" -o "$OUTDIR/ports.txt" || true
ports_ct=$(wc -l < "$OUTDIR/ports.txt")
echo "    Hosts with open ports: ${ports_ct}"

# ---------- 4. HTTP/TLS tech fingerprint ----------
echo "[+] Step 4: HTTPX tech fingerprint..."
httpx -silent -l "$OUTDIR/resolved.txt" -tech-detect -status-code -title -tls-probe -o "$OUTDIR/httpx.txt"
tech_ct=$(wc -l < "$OUTDIR/httpx.txt")
echo "    httpx entries: ${tech_ct}"

# ---------- 5. URL & Parameter Collection ----------
echo "[+] Step 5: URL harvest (waybackurls + gau + gauplus)..."
cat "$OUTDIR/resolved.txt" | waybackurls > "$OUTDIR/urls_wayback.txt"
cat "$OUTDIR/resolved.txt" | gau --subs > "$OUTDIR/urls_gau.txt"
gauplus -subs -o "$OUTDIR/urls_gauplus.txt" $(cat "$OUTDIR/resolved.txt" | head -n 1) >/dev/null 2>&1 || true
cat "$OUTDIR"/urls_*.txt | sort -u > "$OUTDIR/urls.txt"
url_ct=$(wc -l < "$OUTDIR/urls.txt")
echo "    Total unique URLs: ${url_ct}"

# Parameter breakdown
echo "[+]    Filtering parameters with gf..."
cat "$OUTDIR/urls.txt" | gf xss > "$OUTDIR/params_xss.txt"
cat "$OUTDIR/urls.txt" | gf sqli > "$OUTDIR/params_sqli.txt"
cat "$OUTDIR/urls.txt" | gf ssrf > "$OUTDIR/params_ssrf.txt"
xss_ct=$(wc -l < "$OUTDIR/params_xss.txt")
sqli_ct=$(wc -l < "$OUTDIR/params_sqli.txt")
ssrf_ct=$(wc -l < "$OUTDIR/params_ssrf.txt")
echo "    XSS:$xss_ct | SQLi:$sqli_ct | SSRF:$ssrf_ct"

# List JS files
grep '\.js$' "$OUTDIR/urls.txt" > "$OUTDIR/js_files.txt"
js_ct=$(wc -l < "$OUTDIR/js_files.txt")
echo "    JS file links: ${js_ct}"

# ---------- 6. Summary ----------
summary="$OUTDIR/SUMMARY.txt"
cat <<EOF > "$summary"
[ FULL RECON SUMMARY ]      Target: ${domain}
Timestamp           : $(date)
----------------------------------------------
Subdomains found    : ${subs_ct}
Live hosts          : ${live_ct}
Hosts with ports    : ${ports_ct}
HTTPX fingerprints  : ${tech_ct}
Collected URLs      : ${url_ct}
  • XSS params      : ${xss_ct}
  • SQLi params     : ${sqli_ct}
  • SSRF params     : ${ssrf_ct}
JS file count       : ${js_ct}
Output directory    : ${OUTDIR}
EOF

echo "=============================================="
cat "$summary"
echo "=============================================="
echo "[✓] Recon complete • All raw files + SUMMARY.txt are in ${OUTDIR}"
