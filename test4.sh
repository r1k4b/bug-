#!/usr/bin/env bash
# Final Recon Tool v6.2 - Fully Checked & Hardened

# --- Speed Configuration (Balanced for Speed & Stealth) ---
HTTPX_THREADS=250
NUCLEI_CONCURRENCY=200
TOP_PORTS=1000

# --- Telegram Bot Configuration ---
# ⚠️ WARNING: This token has been publicly exposed and is NOT secure.
TELEGRAM_BOT_TOKEN="7481472810:AAFIkTDTlb_pQbmtN-Yz8SWm-6sE_0tmn-U" 
TELEGRAM_CHAT_ID="5002868545"

# --- Setup ---
set -Eeuo pipefail
shopt -s inherit_errexit

# --- Usage Check ---
if [[ $# -lt 1 || "$1" =~ ^(-h|--help)$ ]]; then
    echo "Usage: $0 <domain>"
    echo "Example: ./vps_recon.sh example.com"
    exit 1
fi
domain="$1"

# --- Directory Setup ---
read -rp "🔸 আউটপুট ফোল্ডারের পাথ দিন (e.g. /root/bug_bounty): " base_dir
if [[ -z "$base_dir" ]]; then
    echo "✖️ পাথ খালি রাখা যাবে না" >&2
    exit 1
fi

scan_dir="$base_dir/${domain}_scan_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$scan_dir" || { echo "✖️ '$scan_dir' তৈরি করা যাচ্ছে না" >&2; exit 1; }

log(){ printf '\n\e[1;36m%s\e[0m\n' "--- $* ---"; }
info(){ printf '\e[1;33m[%s] %s\e[0m\n' "$(date +'%H:%M:%S')" "$*"; }
error(){ printf '\e[1;31m[ERROR] %s\e[0m\n' "$*"; }

# --- Dependency Check ---
required_tools=(subfinder assetfinder dnsx httpx naabu nmap katana gau gf nuclei sqlmap dalfox subzy zip curl)
info "Checking for required tools..."
for tool in "${required_tools[@]}"; do
    if ! command -v "$tool" &>/dev/null; then
        error "প্রয়োজনীয় টুল ইন্সটল নেই: $tool"
        exit 1
    fi
done

# --- GF Pattern Check ---
if ! [[ -d "$HOME/.gf" ]] || ! ls -A "$HOME/.gf"/*.json &>/dev/null; then
    error "GF প্যাটার্ন খুঁজে পাওয়া যাচ্ছে না ($HOME/.gf)।"
    error "প্রথমে 'gf -update' এবং অন্যান্য প্যাটার্ন ইন্সটল করুন।"
    exit 1
fi

info "✅ All tools and patterns are ready. Starting scan for '$domain'."
info "Output Directory → $scan_dir"

#<editor-fold desc="Scanning Steps 1-9">
#──────── [1] Subdomain Enumeration ────────#
log "ধাপ ১/১০: Subdomain খোঁজা হচ্ছে..."
(subfinder -d "$domain" -silent; assetfinder --subs-only "$domain" 2>/dev/null) \
    | sort -u > "$scan_dir/subdomains.txt"
subdomains_found=$(wc -l < "$scan_dir/subdomains.txt")
info "✅ মোট $subdomains_found টি ইউনিক সাবডোমেইন পাওয়া গেছে।"

#──────── [2] Host & Port Discovery ────────#
log "ধাপ ২/১০: লাইভ হোস্ট এবং পোর্ট খোঁজা হচ্ছে..."
dnsx -l "$scan_dir/subdomains.txt" -silent -resp-only -a -o "$scan_dir/resolved.txt"
httpx -l "$scan_dir/resolved.txt" -silent -threads "$HTTPX_THREADS" -o "$scan_dir/live_hosts.txt"
info "Naabu দিয়ে টপ $TOP_PORTS টি পোর্ট স্ক্যান করা হচ্ছে..."
naabu -l "$scan_dir/resolved.txt" -top-ports "$TOP_PORTS" -silent -o "$scan_dir/ports.txt"

#──────── [3] Nmap Service Scanning ────────#
log "ধাপ ৩/১০: Nmap দিয়ে সার্ভিস স্ক্যান করা হচ্ছে..."
if [[ -s "$scan_dir/ports.txt" ]]; then
    nmap -sV -sC -iL "$scan_dir/ports.txt" -oA "$scan_dir/nmap_scan" -Pn > "$scan_dir/nmap.log" 2>&1 || true
    info "Nmap স্ক্যান সম্পন্ন। লগ ফাইল: $scan_dir/nmap.log"
else
    info "    কোনো খোলা পোর্ট পাওয়া যায়নি, Nmap স্কিপ করা হলো।"
fi

#──────── [4] URL Discovery & JS Files ────────#
log "ধাপ ৪/১০: URL এবং JS ফাইল খোঁজা হচ্ছে..."
(gau --subs "$domain" 2>/dev/null; katana -u "https://$domain" -silent -jc -d 2) \
    | sort -u > "$scan_dir/all_urls.txt"
grep -Ei '\.js(\?|$)' "$scan_dir/all_urls.txt" | sort -u > "$scan_dir/js_urls.txt"
info "URL খোঁজা সম্পন্ন।"

#──────── [5] Secret Scanning with Nuclei ────────#
log "ধাপ ৫/১০: সংবেদনশীল তথ্য (Secrets) স্ক্যান করা হচ্ছে..."
if [[ -s "$scan_dir/all_urls.txt" ]]; then
    nuclei -l "$scan_dir/all_urls.txt" -t exposures/ -c "$NUCLEI_CONCURRENCY" | tee -a "$scan_dir/secrets_report.txt" || true
else
    info "    URL পাওয়া যায়নি, Secret Scanning স্কিপ করা হলো।"
fi

#──────── [6] Specialized Parameter Scanning ────────#
log "ধাপ ৬/১০: XSS এবং SQLi টার্গেট স্ক্যান করা হচ্ছে..."
cat "$scan_dir/all_urls.txt" | gf sqli > "$scan_dir/sqli_targets.txt" || true
cat "$scan_dir/all_urls.txt" | gf xss > "$scan_dir/xss_targets.txt" || true
if [[ -s "$scan_dir/xss_targets.txt" ]]; then
    info "Dalfox দিয়ে XSS স্ক্যান চলছে..."
    dalfox file "$scan_dir/xss_targets.txt" | tee -a "$scan_dir/dalfox_report.txt" || true
fi
if [[ -s "$scan_dir/sqli_targets.txt" ]]; then
    info "SQLmap দিয়ে SQL Injection স্ক্যান চলছে..."
    sqlmap -m "$scan_dir/sqli_targets.txt" --batch --random-agent --level=2 --risk=1 --output-dir="$scan_dir/sqlmap_out" --disable-coloring || true
fi

#──────── [7] General Vulnerability Scan ────────#
log "ধাপ ৭/১০: সাধারণ দুর্বলতা (Vulnerability) স্ক্যান করা হচ্ছে..."
if [[ -s "$scan_dir/live_hosts.txt" ]]; then
    nuclei -l "$scan_dir/live_hosts.txt" -severity low,medium,high,critical \
           -c "$NUCLEI_CONCURRENCY" | tee -a "$scan_dir/nuclei_report.txt" || true
else
    info "    লাইভ হোস্ট পাওয়া যায়নি, Nuclei স্কিপ করা হলো।"
fi

#──────── [8] Subdomain Takeover Scan ────────#
log "ধাপ ৮/১০: Subdomain Takeover স্ক্যান করা হচ্ছে..."
if [[ -s "$scan_dir/subdomains.txt" ]]; then
    subzy run --targets "$scan_dir/subdomains.txt" | tee -a "$scan_dir/takeover_report.txt" || true
else
    info "    সাবডোমেইন পাওয়া যায়নি, Takeover Scan স্কিপ করা হলো।"
fi

#──────── [9] Auto Zipping ────────#
log "ধাপ ৯/১০: রিপোর্ট জিপ করা হচ্ছে..."
zip_file_path="$base_dir/${domain}_report_final.zip"
zip -rq "$zip_file_path" "$scan_dir"
#</editor-fold>

# --- Final Summary Data ---
live_hosts_found=$(wc -l < "$scan_dir/live_hosts.txt" 2>/dev/null || echo 0)
open_ports_found=$(wc -l < "$scan_dir/ports.txt" 2>/dev/null || echo 0)
nuclei_findings=$(grep -c ']' "$scan_dir/nuclei_report.txt" 2>/dev/null || echo 0)
secrets_found=$(grep -c ']' "$scan_dir/secrets_report.txt" 2>/dev/null || echo 0)
takeover_findings=$(grep -ci 'VULNERABLE' "$scan_dir/takeover_report.txt" 2>/dev/null || echo 0)

#<editor-fold desc="Terminal Summary">
# --- Terminal Summary Display ---
clear
log "✅ সমস্ত কাজ সম্পন্ন!"
echo "--------------------------------------------------------"
echo "📊 SCAN SUMMARY FOR: $domain"
echo "--------------------------------------------------------"
echo "📁 Full Report Saved in: $scan_dir"
echo "📦 Zipped Report: $zip_file_path"
echo ""
echo "KEY FINDINGS:"
echo "-----------------"
echo "   - মোট ইউনিক সাবডোমেইন পাওয়া গেছে : $subdomains_found"
echo "   - লাইভ ওয়েব হোস্ট পাওয়া গেছে      : $live_hosts_found"
echo "   - খোলা পোর্ট পাওয়া গেছে         : $open_ports_found"
echo "   - Nuclei ফাইন্ডিংস (General): $nuclei_findings"
echo "   - Secrets/Exposures পাওয়া গেছে   : $secrets_found"
echo "   - সম্ভাব্য Takeover পাওয়া গেছে    : $takeover_findings"
echo "--------------------------------------------------------"
#</editor-fold>

#──────── [10] Send Telegram Notification ────────#
log "ধাপ ১০/১০: টেলিগ্রাম নোটিফিকেশন পাঠানো হচ্ছে..."
if [[ -n "$TELEGRAM_BOT_TOKEN" && -n "$TELEGRAM_CHAT_ID" ]]; then
    # Improved message formatting using a heredoc
    summary_message=$(cat <<EOF
*📊 Scan Summary for: ${domain}*

*KEY FINDINGS:*
\`\`\`
- Unique Subdomains: ${subdomains_found}
- Live Web Hosts   : ${live_hosts_found}
- Open Ports Found : ${open_ports_found}
- Nuclei Findings  : ${nuclei_findings}
- Secrets/Exposures: ${secrets_found}
- Possible Takeovers: ${takeover_findings}
\`\`\`

Full report is attached.
EOF
    )

    # Send the summary message and check for success
    if curl -s -X POST "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
        -d "chat_id=${TELEGRAM_CHAT_ID}" \
        -d "text=${summary_message}" \
        -d "parse_mode=Markdown" > /dev/null; then
        info "✅ টেলিগ্রাম মেসেজ সফলভাবে পাঠানো হয়েছে।"
    else
        error "❌ টেলিগ্রাম মেসেজ পাঠাতে ব্যর্থ।"
    fi

    # Send the zip file and check for success
    if curl -s -X POST "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendDocument" \
        -F "chat_id=${TELEGRAM_CHAT_ID}" \
        -F "document=@${zip_file_path}" > /dev/null; then
        info "✅ টেলিগ্রাম রিপোর্ট ফাইল সফলভাবে পাঠানো হয়েছে।"
    else
        error "❌ টেলিগ্রাম রিপোর্ট ফাইল পাঠাতে ব্যর্থ।"
    fi
else
    info "    টেলিগ্রাম টোকেন বা চ্যাট আইডি দেওয়া হয়নি, নোটিফিকেশন স্কিপ করা হলো।"
fi
