#!/usr/bin/env bash
# bughunt_auto.sh
# Post‑Recon Bug Hunting Automation
#
# Prerequisites:
#   - recon output directory produced by recon_full.sh
#   - Required tools installed: nuclei, dalfox, sqlmap, ffuf, trufflehog, SecretFinder, corsy,
#     interactsh-client, subzy (optional), xsstrike (optional)
#
# Usage:
#   ./bughunt_auto.sh <RECON_OUT_DIR> [threads]
#
#   threads : optional max parallel ffuf threads (default 100)

set -euo pipefail

OUTDIR="${1:-}"
THREADS="${2:-100}"

if [[ -z "$OUTDIR" || ! -d "$OUTDIR" ]]; then
  echo "Usage: $0 <recon_output_directory> [threads]"
  exit 1
fi

domain=$(basename "$OUTDIR" | cut -d'_' -f2)
BUGDIR="${OUTDIR}/bug_results"
mkdir -p "$BUGDIR"

log() { echo -e "\033[1;32m[+] $*\033[0m"; }

#############################################
# 1. Subdomain Takeover (nuclei + subzy)
#############################################
log "Subdomain takeover scan..."
if [[ -f "$OUTDIR/subdomains.txt" ]]; then
  nuclei -silent -t takeovers/ -l "$OUTDIR/subdomains.txt" -o "$BUGDIR/takeovers_nuclei.txt" || true
  # optional subzy
  if command -v subzy >/dev/null 2>&1; then
    subzy run --targets "$OUTDIR/subdomains.txt" --hide_fails > "$BUGDIR/takeovers_subzy.txt" || true
  fi
fi

#############################################
# 2. Exposed files & Default credentials
#############################################
log "Nuclei exposures + default‑logins ..."
if [[ -f "$OUTDIR/resolved.txt" ]]; then
  nuclei -silent -t exposures/ -l "$OUTDIR/resolved.txt" -o "$BUGDIR/exposures.txt" || true
  nuclei -silent -t default-logins/ -l "$OUTDIR/resolved.txt" -o "$BUGDIR/default_logins.txt" || true
fi

#############################################
# 3. Dalfox XSS fuzz
#############################################
log "XSS fuzz (Dalfox)..."
if [[ -f "$OUTDIR/params_xss.txt" ]]; then
  dalfox file "$OUTDIR/params_xss.txt" --skip-bav -o "$BUGDIR/dalfox_xss.txt" || true
fi

#############################################
# 4. SQLi auto‑scan (sqlmap)
#############################################
log "SQLi scan (sqlmap)..."
if [[ -f "$OUTDIR/params_sqli.txt" ]]; then
  sqlmap -m "$OUTDIR/params_sqli.txt" --batch --risk=2 --level=2 --threads=3 --output-dir="$BUGDIR/sqlmap_out" || true
fi

#############################################
# 5. Secrets & Tokens in JS
#############################################
log "Secrets scan in JS (SecretFinder + trufflehog)..."
if [[ -f "$OUTDIR/js_files.txt" ]]; then
  python3 $(which SecretFinder.py 2>/dev/null || echo SecretFinder.py) -i "$OUTDIR/js_files.txt" -o cli > "$BUGDIR/js_secrets.txt" 2>/dev/null || true
  while read -r jsurl; do
    curl -s "$jsurl" | trufflehog stdin --regex --entropy=False --json >> "$BUGDIR/trufflehog.json" || true
  done < "$OUTDIR/js_files.txt"
fi

#############################################
# 6. CORS misconfiguration
#############################################
log "CORS scan (Corsy)..."
if [[ -f "$OUTDIR/resolved.txt" ]]; then
  corsy -i "$OUTDIR/resolved.txt" -o "$BUGDIR/corsy_report" >/dev/null 2>&1 || true
fi

#############################################
# 7. Dir brute (ffuf) – first 30 live hosts
#############################################
log "Directory brute‑force (ffuf)..."
if [[ -f "$OUTDIR/resolved.txt" ]]; then
  head -n 30 "$OUTDIR/resolved.txt" | while read -r host; do
    ffuf -mc all -t "$THREADS" -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt       -u "https://${host}/FUZZ" -o "$BUGDIR/ffuf_${host//[^a-zA-Z0-9]/_}.json" 2>/dev/null || true
  done
fi

#############################################
# 8. Port CVE scan (nuclei cves/)
#############################################
log "Service CVE scan..."
if [[ -f "$OUTDIR/ports.txt" ]]; then
  # build httpx host:port list
  awk '{print "http://"$1":"$2}' "$OUTDIR/ports.txt" > "$BUGDIR/hostports.txt"
  nuclei -silent -t cves/ -l "$BUGDIR/hostports.txt" -o "$BUGDIR/service_cves.txt" || true
fi

#############################################
# 9. Blind SSRF / XSS (Interactsh)
#############################################
if command -v interactsh-client >/dev/null 2>&1 && [[ -f "$OUTDIR/params_ssrf.txt" ]]; then
  log "Blind SSRF / XSS using Interactsh..."
  interactsh-client -q -o "$BUGDIR/int.url"
  IURL=$(cat "$BUGDIR/int.url")
  nuclei -silent -t vulnerabilities/ -l "$OUTDIR/params_ssrf.txt" -interactsh-url "$IURL" -o "$BUGDIR/ssrf_blind.txt" || true
fi

#############################################
# Summary
#############################################
log "Bug‑hunt automation finished!"
echo "Results directory: $BUGDIR"
