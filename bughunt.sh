#!/bin/bash

# Fast Bug Bounty Methodology Script
# Usage: ./bughunt.sh example.com

domain=$1

if [ -z "$domain" ]; then
  echo "Usage: $0 example.com"
  exit 1
fi

echo "[+] Subdomain Enumeration"
subfinder -d $domain -o subs.txt

echo "[+] Getting Wayback URLs"
cat subs.txt | waybackurls > wayback.txt

echo "[+] Filtering Parameters with GF"
cat wayback.txt | gf xss > xss.txt
cat wayback.txt | gf sqli > sqli.txt
cat wayback.txt | grep '\.js$' > js.txt

echo "[+] Nuclei Scan - Exposures"
nuclei -t exposures/ -l subs.txt -o exposures.txt

echo "[+] Nuclei Scan - Default Logins"
nuclei -t default-logins/ -l subs.txt -o logins.txt

echo "[+] Nuclei Scan - Param-Based XSS"
nuclei -t vulnerabilities/ -l xss.txt -o vuln_xss.txt

echo "[+] Checking JS files manually for token or API leak"
while read url; do curl -s "$url" | grep -Ei 'api|key|token'; done < js.txt

echo "[+] Bug Hunting Automation Completed!"
