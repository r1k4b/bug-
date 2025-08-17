#!/usr/bin/env bash
# recon_plus_bughunt.sh
# Combines recon_full.sh + bughunt_auto.sh (sequential bughunt)

set -uo pipefail

TARGET="${1:-}"
[[ -z "$TARGET" ]] && { echo "Usage: $0 <domain>"; exit 1; }

# ==== Recon ====
./recon_full.sh "$TARGET" || { echo "[FAIL] Recon failed"; exit 1; }

# ==== Detect latest recon folder ====
OUTDIR=$(ls -td results_${TARGET}_* | head -n1)
[[ -d "$OUTDIR" ]] || { echo "[FAIL] Recon output directory not found"; exit 1; }

# ==== Bughunt ====
THREADS=100  # or adjust as needed
BUGDIR="${OUTDIR}/bug_results"
mkdir -p "$BUGDIR"

log() { echo -e "\033[1;32m[+] $*\033[0m"; }

log "Running subdomain takeover scan..."
[[ -f "$OUTDIR/subdomains.txt" ]] && nuclei -silent -t takeovers/ -l "$OUTDIR/subdomains.txt" -o "$BUGDIR/takeovers_nuclei.txt" || true
command -v subzy >/dev/null && subzy run --targets "$OUTDIR/subdomains.txt" --hide_fails > "$BUGDIR/takeovers_subzy.txt" || true

log "Running exposure + default login checks..."
[[ -f "$OUTDIR/resolved.txt" ]] && {
  nuclei -silent -t exposures/ -l "$OUTDIR/resolved.txt" -o "$BUGDIR/exposures.txt"
  nuclei -silent -t default-logins/ -l "$OUTDIR/resolved.txt" -o "$BUGDIR/default_logins.txt"
}

log "Running Dalfox XSS fuzzing..."
[[ -f "$OUTDIR/params_xss.txt" ]] && dalfox file "$OUTDIR/params_xss.txt" --skip-bav -o "$BUGDIR/dalfox_xss.txt"

log "Running SQLmap scan..."
[[ -f "$OUTDIR/params_sqli.txt" ]] && sqlmap -m "$OUTDIR/params_sqli.txt" --batch --risk=2 --level=2 --threads=3 --output-dir="$BUGDIR/sqlmap_out"

log "Scanning for JS secrets..."
[[ -f "$OUTDIR/js_files.txt" ]] && {
  python3 $(which SecretFinder.py 2>/dev/null || echo SecretFinder.py) -i "$OUTDIR/js_files.txt" -o cli > "$BUGDIR/js_secrets.txt"
  while read -r jsurl; do
    curl -s "$jsurl" | trufflehog stdin --regex --entropy=False --json >> "$BUGDIR/trufflehog.json" || true
  done < "$OUTDIR/js_files.txt"
}

log "Running CORS scan..."
[[ -f "$OUTDIR/resolved.txt" ]] && corsy -i "$OUTDIR/resolved.txt" -o "$BUGDIR/corsy_report" >/dev/null 2>&1

log "Running directory brute-force (ffuf)..."
[[ -f "$OUTDIR/resolved.txt" ]] && head -n 30 "$OUTDIR/resolved.txt" | while read -r host; do
  ffuf -mc all -t "$THREADS" -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
    -u "https://${host}/FUZZ" -o "$BUGDIR/ffuf_${host//[^a-zA-Z0-9]/_}.json" 2>/dev/null
done

log "Running CVE scan (nuclei cves)..."
[[ -f "$OUTDIR/ports.txt" ]] && {
  awk '{print "http://"$1":"$2}' "$OUTDIR/ports.txt" > "$BUGDIR/hostports.txt"
  nuclei -silent -t cves/ -l "$BUGDIR/hostports.txt" -o "$BUGDIR/service_cves.txt"
}

log "Running Interactsh blind SSRF/XSS..."
if command -v interactsh-client >/dev/null 2>&1 && [[ -f "$OUTDIR/params_ssrf.txt" ]]; then
  interactsh-client -q -o "$BUGDIR/int.url"
  IURL=$(cat "$BUGDIR/int.url")
  nuclei -silent -t vulnerabilities/ -l "$OUTDIR/params_ssrf.txt" -interactsh-url "$IURL" -o "$BUGDIR/ssrf_blind.txt"
fi

log "[✓] All tasks complete. Results in: $BUGDIR"
