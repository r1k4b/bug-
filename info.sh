#!/usr/bin/env bash
# Final Recon-Only Tool v2 - Saves all output to a single file

# --- Configuration and Setup ---
set -Eeuo pipefail
shopt -s inherit_errexit

# --- Usage Check ---
if [[ $# -lt 1 || "$1" =~ ^(-h|--help)$ ]]; then
    echo "Usage: $0 <domain>"
    echo "Example: ./recon_only.sh example.com"
    exit 1
fi
domain="$1"

# --- Directory Setup ---
read -rp "🔸 আউটপুট ফোল্ডারের পাথ দিন (e.g. /home/user/recon_data): " base_dir
if [[ -z "$base_dir" ]]; then
    echo "✖️ পাথ খালি রাখা যাবে না" >&2
    exit 1
fi

scan_dir="$base_dir/${domain}_recon_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$scan_dir" || { echo "✖️ '$scan_dir' তৈরি করা যাচ্ছে না" >&2; exit 1; }

# --- Define the single output file ---
OUTPUT_FILE="$scan_dir/${domain}_full_report.txt"

log(){ printf '%(%Y-%m-%d %H:%M:%S)T %s\n' -1 "$*"; }

# --- Dependency Check ---
required_tools=(subfinder assetfinder dnsx httpx naabu nmap katana gau)
log "[*] Checking for required tools..."
for tool in "${required_tools[@]}"; do
    if ! command -v "$tool" &>/dev/null; then
        echo "❌ প্রয়োজনীয় টুল ইন্সটল নেই: $tool" >&2
        exit 1
    fi
done
log "✅ All required tools are installed."

log "[*] Recon আউটপুট ফোল্ডার → $scan_dir"
log "📝 সব ফলাফল এই ফাইলে সেভ করা হবে → $OUTPUT_FILE"
echo "Scan for $domain started at $(date)" > "$OUTPUT_FILE"

#──────── [1] Subdomain Enumeration ────────#
log "[1/4] Subdomain Enumeration (subfinder + assetfinder)..."
echo -e "\n\n--- [SUBDOMAINS] ---\n" >> "$OUTPUT_FILE"
(subfinder -d "$domain" -silent; assetfinder --subs-only "$domain" 2>/dev/null) \
    | sort -u | tee "$scan_dir/subdomains.txt" >> "$OUTPUT_FILE"

#──────── [2] Host & Port Discovery ────────#
log "[2/4] Host & Port Discovery (dnsx, httpx, naabu)..."
dnsx -l "$scan_dir/subdomains.txt" -silent -resp-only -a -o "$scan_dir/resolved.txt"
echo -e "\n\n--- [LIVE WEB HOSTS (httpx)] ---\n" >> "$OUTPUT_FILE"
httpx -l "$scan_dir/resolved.txt" -silent -threads 100 | tee "$scan_dir/live_hosts.txt" >> "$OUTPUT_FILE"
echo -e "\n\n--- [OPEN PORTS (naabu)] ---\n" >> "$OUTPUT_FILE"
naabu -l "$scan_dir/resolved.txt" -top-ports 1000 -silent | tee "$scan_dir/ports.txt" >> "$OUTPUT_FILE"

#──────── [3] Nmap Service Scanning ────────#
log "[3/4] Nmap Service Scanning..."
if [[ -s "$scan_dir/ports.txt" ]]; then
    echo -e "\n\n--- [NMAP SERVICE SCAN] ---\n" >> "$OUTPUT_FILE"
    nmap -sV -sC -iL "$scan_dir/ports.txt" -oN "$scan_dir/nmap_scan.txt" >/dev/null 2>&1 || true
    cat "$scan_dir/nmap_scan.txt" >> "$OUTPUT_FILE"
else
    log "    কোনো খোলা পোর্ট পাওয়া যায়নি, Nmap স্কিপ করা হলো।"
fi

#──────── [4] URL Discovery ────────#
log "[4/4] URL Discovery (gau, katana)..."
echo -e "\n\n--- [URLs] ---\n" >> "$OUTPUT_FILE"
(gau --subs "$domain" 2>/dev/null; katana -u "https://$domain" -silent -jc -d 2) \
    | sort -u >> "$OUTPUT_FILE"

# --- Finalizing ---
# No zipping needed.

# --- Final Summary ---
clear
log "✅ Reconnaissance সম্পন্ন!"
echo "--------------------------------------------------------"
echo "📊 RECON SUMMARY FOR: $domain"
echo "--------------------------------------------------------"
echo "📁 Full Report Saved in a single file:"
echo "   $OUTPUT_FILE"
echo ""
echo "KEY DATA COLLECTED:"
echo "-----------------"
subdomains_found=$(wc -l < "$scan_dir/subdomains.txt" 2>/dev/null || echo 0)
live_hosts_found=$(wc -l < "$scan_dir/live_hosts.txt" 2>/dev/null || echo 0)
open_ports_found=$(wc -l < "$scan_dir/ports.txt" 2>/dev/null || echo 0)

# Counting URLs from the final report file is more efficient
urls_found=$(grep -cE '^http' "$OUTPUT_FILE" 2>/dev/null || echo 0)

echo "   - মোট সাবডোমেইন পাওয়া গেছে  : $subdomains_found"
echo "   - লাইভ ওয়েব হোস্ট পাওয়া গেছে    : $live_hosts_found"
echo "   - খোলা পোর্ট পাওয়া গেছে       : $open_ports_found"
echo "   - মোট URL পাওয়া গেছে          : $urls_found"
echo "--------------------------------------------------------"
echo "এখন আপনি এই একটি ফাইল বিশ্লেষণ করে ম্যানুয়ালি অ্যাটাক চালাতে পারেন।"
