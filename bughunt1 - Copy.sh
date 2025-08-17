#!/bin/bash

# Check if a domain was provided
domain="$1"
if [ -z "$domain" ]; then
  echo "Usage: $0 example.com"
  exit 1
fi

# আউটপুট রাখার ফোল্ডার (পেনড্রাইভে)
# Note: Using forward slashes and quotes to handle spaces in the path correctly.
output_dir="/mnt/d/bug_hunt/bug report/${domain}_scan"
mkdir -p "$output_dir"

# Check if required tools are installed and in PATH
for cmd in subfinder waybackurls gf nuclei curl xargs; do
  if ! command -v "$cmd" &> /dev/null; then
    echo "Error: $cmd is not installed or not in your PATH."
    echo "Please ensure all required tools are installed and accessible."
    exit 1
  fi
done

echo "[+] Starting scan for: $domain"
echo "[+] Results will be saved in: $output_dir"

echo "[+] Running Subdomain Enumeration..."
subfinder -d "$domain" -o "${output_dir}/subdomains.txt" || { echo "Subfinder failed"; exit 1; }
echo "    Found $(wc -l < "${output_dir}/subdomains.txt") subdomains."

echo "[+] Fetching Wayback URLs..."
if [ -s "${output_dir}/subdomains.txt" ]; then
    cat "${output_dir}/subdomains.txt" | waybackurls > "${output_dir}/wayback_urls.txt" || { echo "Waybackurls failed"; }
    if [ -s "${output_dir}/wayback_urls.txt" ]; then
        echo "    Found $(wc -l < "${output_dir}/wayback_urls.txt") URLs."
    fi
else
    echo "    No subdomains found to fetch URLs for."
fi


echo "[+] Filtering for potential vulnerabilities with GF..."
if [ -s "${output_dir}/wayback_urls.txt" ]; then
    cat "${output_dir}/wayback_urls.txt" | gf xss > "${output_dir}/potential_xss.txt"
    cat "${output_dir}/wayback_urls.txt" | gf sqli > "${output_dir}/potential_sqli.txt"
    cat "${output_dir}/wayback_urls.txt" | gf lfi > "${output_dir}/potential_lfi.txt"
    cat "${output_dir}/wayback_urls.txt" | gf ssrf > "${output_dir}/potential_ssrf.txt"
    echo "    GF filtering complete."
else
    echo "    No URLs to filter."
fi

echo "[+] Running Nuclei for high-impact vulnerabilities..."
# Use targeted templates instead of broad categories to avoid out-of-scope issues
nuclei -l "${output_dir}/subdomains.txt" -H "X-HackerOne-Research: rajib_mahmud" -t cves/,technologies/,misconfiguration/ -o "${output_dir}/nuclei_report.txt" -rl 10 || echo "[!] Nuclei scan had some errors."

echo "[+] Scan complete for $domain"