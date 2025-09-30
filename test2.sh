#!/usr/bin/env bash
# Final Recon Tool v2 - With Nmap, Summary, and Subdomain Takeover Scan

# --- Configuration and Setup ---
set -Eeuo pipefail
shopt -s inherit_errexit

# --- Usage Check ---
if [[ $# -lt 1 || "$1" =~ ^(-h|--help)$ ]]; then
    echo "Usage: $0 <domain>"
    echo "Example: ./final_recon.sh example.com"
    exit 1
fi
domain="$1"

# --- Directory Setup ---
read -rp "🔸 আউটপুট ফোল্ডারের পাথ দিন (e.g. /home/user/bug_bounty): " base_dir
if [[ -z "$base_dir" ]]; then
    echo "✖️ পাথ খালি রাখা যাবে না" >&2
    exit 1
fi

scan_dir="$base_dir/${domain}_scan_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$scan_dir" || { echo "✖️ '$scan_dir' তৈরি করা যাচ্ছে না" >&2; exit 1; }

log(){ printf '%(%Y-%m-%d %H:%M:%S)T %s\n' -1 "$*"; }

# --- Dependency Check ---
required_tools=(subfinder assetfinder dnsx httpx naabu nmap katana gau gf nuclei sqlmap dalfox subzy zip)
log "[*] Checking for required tools..."
for tool in "${required_tools[@]}"; do
    if ! command -v "$tool" &>/dev/null; then
        echo "❌ প্রয়োজনীয় টুল ইন্সটল নেই: $tool" >&2
        exit 1
    fi
done
log "✅ All required tools are installed."

log "[*] আউটপুট ফোল্ডার → $scan_dir"

#──────── [1] Subdomain Enumeration ────────#
log "[1/9] Subdomain Enumeration (subfinder + assetfinder)..."
(subfinder -d "$domain" -silent; assetfinder --subs-only "$domain" 2>/dev/null) \
    | sort -u > "$scan_dir/subdomains.txt"

#──────── [2] Host & Port Discovery ────────#
log "[2/9] Host & Port Discovery (dnsx, httpx, naabu)..."
dnsx -l "$scan_dir/subdomains.txt" -silent -resp-only -a -o "$scan_dir/resolved.txt"
httpx -l "$scan_dir/resolved.txt" -silent -threads 100 -o "$scan_dir/live_hosts.txt"
naabu -l "$scan_dir/resolved.txt" -top-ports 100 -silent -o "$scan_dir/ports.txt"

#──────── [3] Nmap Service Scanning ────────#
log "[3/9] Nmap Service Scanning..."
if [[ -s "$scan_dir/ports.txt" ]]; then
    nmap -sV -sC -iL "$scan_dir/ports.txt" -oA "$scan_dir/nmap_scan" >/dev/null 2>&1 || true
else
    log "    কোনো খোলা পোর্ট পাওয়া যায়নি, Nmap স্কিপ করা হলো।"
fi

#──────── [4] URL Discovery & JS Files ────────#
log "[4/9] URL Discovery & JS Files (gau, katana)..."
(gau --subs "$domain" 2>/dev/null; katana -u "https://$domain" -silent -jc -d 2) \
    | sort -u > "$scan_dir/all_urls.txt"
grep -Ei '\.js(\?|$)' "$scan_dir/all_urls.txt" | sort -u > "$scan_dir/js_urls.txt"

#──────── [5] Secret Scanning with Nuclei ────────#
log "[5/9] Secret Scanning with Nuclei (Exposures)..."
if [[ -s "$scan_dir/all_urls.txt" ]]; then
    nuclei -l "$scan_dir/all_urls.txt" -t exposures/ -o "$scan_dir/secrets_report.txt" -silent || true
else
    log "    URL পাওয়া যায়নি, Secret Scanning স্কিপ করা হলো।"
fi

#──────── [6] Specialized Parameter Scanning ────────#
log "[6/9] Specialized Parameter Scanning (gf, Dalfox, SQLmap)..."
cat "$scan_dir/all_urls.txt" | gf sqli > "$scan_dir/sqli_targets.txt" || true
cat "$scan_dir/all_urls.txt" | gf xss > "$scan_dir/xss_targets.txt" || true
if [[ -s "$scan_dir/xss_targets.txt" ]]; then
    dalfox file "$scan_dir/xss_targets.txt" -o "$scan_dir/dalfox_report.txt" || true
fi
if [[ -s "$scan_dir/sqli_targets.txt" ]]; then
    sqlmap -m "$scan_dir/sqli_targets.txt" --batch --random-agent --level=2 --risk=1 --output-dir="$scan_dir/sqlmap_out" || true
fi

#──────── [7] General Vulnerability Scan ────────#
log "[7/9] General Vulnerability Scan (Nuclei)..."
nuclei -l "$scan_dir/live_hosts.txt" -severity medium,high,critical \
       -c 60 -o "$scan_dir/nuclei_report.txt" -silent

#──────── [8] Subdomain Takeover Scan ────────#
log "[8/9] Subdomain Takeover Scan (subzy)..."
if [[ -s "$scan_dir/subdomains.txt" ]]; then
    subzy run --targets "$scan_dir/subdomains.txt" --output "$scan_dir/takeover_report.txt" || true
else
    log "    সাবডোমেইন পাওয়া যায়নি, Takeover Scan স্কিপ করা হলো।"
fi

#──────── [9] Auto Zipping & Summary ────────#
log "[9/9] Zipping report and creating summary..."
zip -rq "$base_dir/${domain}_report_final.zip" "$scan_dir"

# --- Final Summary ---
clear
log "✅ সমস্ত কাজ সম্পন্ন!"
echo "--------------------------------------------------------"
echo "📊 SCAN SUMMARY FOR: $domain"
echo "--------------------------------------------------------"
echo "📁 Full Report Saved in: $scan_dir"
echo "📦 Zipped Report: $base_dir/${domain}_report_final.zip"
echo ""
echo "KEY FINDINGS:"
echo "-----------------"
subdomains_found=$(wc -l < "$scan_dir/subdomains.txt" 2>/dev/null || echo 0)
live_hosts_found=$(wc -l < "$scan_dir/live_hosts.txt" 2>/dev/null || echo 0)
open_ports_found=$(wc -l < "$scan_dir/ports.txt" 2>/dev/null || echo 0)
nuclei_findings=$(grep -c ']' "$scan_dir/nuclei_report.txt" 2>/dev/null || echo 0)
secrets_found=$(grep -c ']' "$scan_dir/secrets_report.txt" 2>/dev/null || echo 0)
takeover_findings=$(wc -l < "$scan_dir/takeover_report.txt" 2>/dev/null || echo 0)

echo "   - মোট সাবডোমেইন পাওয়া গেছে  : $subdomains_found"
echo "   - লাইভ ওয়েব হোস্ট পাওয়া গেছে    : $live_hosts_found"
echo "   - খোলা পোর্ট পাওয়া গেছে       : $open_ports_found"
echo "   - Nuclei ফাইন্ডিংস (General): $nuclei_findings"
echo "   - Secrets/Exposures পাওয়া গেছে : $secrets_found"
echo "   - সম্ভাব্য Takeover পাওয়া গেছে  : $takeover_findings"
echo "--------------------------------------------------------"
