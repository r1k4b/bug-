#!/usr/bin/env python3
import os
import re
import argparse
import requests
import logging
import random
import urllib3
from urllib3.exceptions import InsecureRequestWarning
from concurrent.futures import ThreadPoolExecutor
from typing import List, Dict
from colorama import Fore, Style, init
import threading

# Disable insecure request warnings
urllib3.disable_warnings(InsecureRequestWarning)
init(autoreset=True)

# Predefined file paths to scan
BUILT_IN_FILES: List[str] = [
    ".env", ".env.local", ".git/config", ".gitignore", "config.json", "credentials.json",
    "local.env", "backup.zip", "db.sqlite", "dump.sql", "database.sql", "backup.tar.gz",
    ".terraform.tfstate", "docker-compose.yml", "kube/config", "settings.py", "credentials.yml",
    ".npmrc", "npm-shrinkwrap.json", ".bash_history", ".aws/credentials", ".htpasswd",
    ".htaccess", ".ftpconfig", ".DS_Store", "id_rsa", "id_dsa", "id_ed25519", "private.key",
    "wp-config.php", "log.zip", "debug.log", "payment.env", "braintree.env", "square.conf",
    "robots.txt", "sitemap.xml"
]

# Regex patterns for API key extraction
KEY_PATTERNS: Dict[str, re.Pattern] = {
    "AWS Access Key ID": re.compile(r"AKIA[0-9A-Z]{16}"),
    "AWS Secret Access Key": re.compile(r"(?<![A-Z0-9])[A-Z0-9]{40}(?![A-Z0-9])"),
    "Github Token": re.compile(r"gh[oprs]_[0-9A-Za-z]{36}"),
    "Heroku API Key": re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"),
    "OpenAI API Key": re.compile(r"sk-[0-9a-zA-Z]{48}"),
    "Google API Key": re.compile(r"AIza[0-9A-Za-z-_]{35}"),
    "GCP Service Account": re.compile(r"\"type\"\s*:\s*\"service_account\""),
    "DigitalOcean Token": re.compile(r"do\.[A-Za-z0-9]{64}"),
    "JWT": re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    "Private Key Block": re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"),
    "Slack Token": re.compile(r"xox[baprs]-[0-9a-zA-Z]{10,48}"),
    "Slack Webhook URL": re.compile(r"https://hooks\.slack\.com/services/[A-Z0-9/]{20,}"),
    "Mailgun API Key": re.compile(r"key-[0-9a-z]{32}"),
    "Twilio API Key": re.compile(r"SK[0-9a-fA-F]{32}"),
    "SendGrid API Key": re.compile(r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}"),
    "Stripe Live": re.compile(r"sk_live_[0-9a-zA-Z]{24}"),
    "Stripe Test": re.compile(r"sk_test_[0-9a-zA-Z]{24}"),
    "Razorpay Live": re.compile(r"rzp_live_[0-9a-zA-Z]{14,32}"),
    "Razorpay Test": re.compile(r"rzp_test_[0-9a-zA-Z]{14,32}"),
    "Paystack Live": re.compile(r"sk_live_[0-9a-z]{32}"),
    "Paystack Test": re.compile(r"sk_test_[0-9a-z]{32}"),
    "Square Access Token": re.compile(r"sq0atp-[0-9A-Za-z_-]{22}"),
    "Square Secret": re.compile(r"sq0csp-[0-9A-Za-z_-]{43}"),
    "Braintree Access Token": re.compile(r"access_token\$production\$[0-9a-z]{16}\$[0-9a-z]{32}"),
    "Flutterwave Secret": re.compile(r"FLWSECK-[A-Za-z0-9]{12}"),
    "Flutterwave Public": re.compile(r"FLWPUBK-[A-Za-z0-9]{12}"),
    "Facebook Access Token": re.compile(r"EAACEdEose0cBA[0-9A-Za-z]{20,}"),
    "Twitter Bearer Token": re.compile(r"AAAAAAAAAAAAAAAAAAAAA[0-9a-zA-Z%]{35,}"),
    "Datadog API Key": re.compile(r"api_key=[0-9a-f]{32}"),
    "PagerDuty Key": re.compile(r"PDI\d{10,}"),
    "Azure Storage Key": re.compile(r"[A-Za-z0-9\+\/]{88}=")
}

# User-Agent pool for requests
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
    "Mozilla/5.0 (X11; Linux x86_64)"
]

# Configure logging
logging.basicConfig(
    filename='scanner.log',
    level=logging.WARNING,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

class BugHuntScanner:
    def __init__(self, targets: List[str], output_dir: str, workers: int = 50):
        self.targets = targets
        self.output_dir = output_dir
        self.workers = workers
        self.session = requests.Session()
        self.lock = threading.Lock()
        self._setup_dirs()

    def _setup_dirs(self):
        os.makedirs(self.output_dir, exist_ok=True)
        os.makedirs(f"{self.output_dir}/LIVE_URLS", exist_ok=True)
        os.makedirs(f"{self.output_dir}/API_KEYS", exist_ok=True)

    def scan(self):
        print(f"{Fore.CYAN}Starting scan on {len(self.targets)} targets with {self.workers} workers...{Style.RESET_ALL}")
        with ThreadPoolExecutor(max_workers=self.workers) as executor:
            executor.map(self.scan_target, self.targets)

    def scan_target(self, target: str):
        target = target.strip()
        if not target:
            return
        for file_path in BUILT_IN_FILES:
            for scheme in ('http://', 'https://'):
                url = f"{scheme}{target}/{file_path}"
                headers = {"User-Agent": random.choice(USER_AGENTS)}
                try:
                    resp = self.session.get(url, headers=headers, timeout=5, verify=False)
                except requests.RequestException:
                    continue

                if resp.status_code == 200:
                    print(f"{Fore.GREEN}[+] Found: {url}{Style.RESET_ALL}")
                    self._record_live_url(url)
                    keys = self._extract_keys(resp.text)
                    if keys:
                        self._save_keys(url, keys)

    def _extract_keys(self, content: str) -> Dict[str, List[str]]:
        found = {}
        for name, pattern in KEY_PATTERNS.items():
            matches = pattern.findall(content)
            if matches:
                found[name] = list(set(matches))
                for m in found[name]:
                    print(f"{Fore.YELLOW}[!] {name}: {m}{Style.RESET_ALL}")
        return found

    def _record_live_url(self, url: str):
        path = os.path.join(self.output_dir, 'LIVE_URLS', 'live_urls.txt')
        with self.lock, open(path, 'a', encoding='utf-8') as f:
            f.write(url + '\n')

    def _save_keys(self, url: str, keys: Dict[str, List[str]]):
        safe_name = url.replace('://', '_').replace('/', '_')
        path = os.path.join(self.output_dir, 'API_KEYS', f"{safe_name}_keys.txt")
        with self.lock, open(path, 'w', encoding='utf-8') as f:
            for name, vals in keys.items():
                for v in vals:
                    f.write(f"{name}: {v}\n")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Automatic Bug Hunt Scanner')
    parser.add_argument('--input', '-i', required=True, help='File with list of URLs or IPs')
    parser.add_argument('--output', '-o', default='output', help='Output directory')
    parser.add_argument('--workers', '-w', type=int, default=50, help='Number of concurrent workers')
    args = parser.parse_args()

    if not os.path.isfile(args.input):
        print(f"{Fore.RED}Input file not found: {args.input}{Style.RESET_ALL}")
        exit(1)

    with open(args.input, 'r', encoding='utf-8') as f:
        targets = [line.strip() for line in f if line.strip()]

    scanner = BugHuntScanner(targets, args.output, workers=args.workers)
    scanner.scan()

