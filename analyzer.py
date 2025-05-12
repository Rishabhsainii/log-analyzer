import re
from collections import defaultdict

LOG_FILE = "logs/sample.log"
FAILED_LOGIN_PATTERN = r'POST /login.* 401'
SQLI_PATTERNS = [r"' OR 1=1", r"UNION SELECT", r"--", r"= '", r"' AND '1'='1"]
XSS_PATTERNS = [r"<script>", r"onerror=", r"alert\(", r"<img", r"document\.cookie"]

failed_logins = defaultdict(int)
sql_injections = []
xss_attacks = []

def detect_attacks(line):
    ip = line.split(' ')[0]

    if re.search(FAILED_LOGIN_PATTERN, line):
        failed_logins[ip] += 1

    for pattern in SQLI_PATTERNS:
        if re.search(pattern, line, re.IGNORECASE):
            sql_injections.append((ip, line.strip()))
            break

    for pattern in XSS_PATTERNS:
        if re.search(pattern, line, re.IGNORECASE):
            xss_attacks.append((ip, line.strip()))
            break

def print_summary():
    print("\n=== Threat Report ===\n")

    for ip, count in failed_logins.items():
        if count >= 5:
            print(f"[!] Brute-force detected from {ip} ({count} failed attempts)")

    for ip, entry in sql_injections:
        print(f"[!] SQL Injection attempt from {ip}: {entry}")

    for ip, entry in xss_attacks:
        print(f"[!] XSS attempt from {ip}: {entry}")

    print("\n[✓] Analysis complete.")
    print(f"→ Brute-force IPs: {len([i for i in failed_logins if failed_logins[i] >= 5])}")
    print(f"→ SQLi Attempts: {len(sql_injections)}")
    print(f"→ XSS Attempts: {len(xss_attacks)}")

def main():
    try:
        with open(LOG_FILE, 'r') as file:
            for line in file:
                detect_attacks(line)
        print_summary()
    except FileNotFoundError:
        print(f"[ERROR] Log file not found: {LOG_FILE}")

if __name__ == "__main__":
    main()
