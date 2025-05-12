# 🛡️ Log Analyzer - Web Attack Detection Tool

A lightweight Python-based log analyzer that scans Apache/Nginx access logs to detect and report:

- 🚨 Brute-force login attempts  
- ⚔️ SQL Injection (SQLi) patterns  
- 🧪 Cross-site Scripting (XSS) payloads

---
# 🚀 Features

- Parses real-world access logs
- Detects OWASP Top 10 threats: XSS, SQLi, brute-force
- Regex-powered payload detection
- Highlights suspicious IPs
- Simple CLI usage with zero dependencies

---
# 🛠️ How to Run

1. Place your web server logs inside the `logs/` directory  
2. Run the analyzer:

```bash
python analyzer.py
---
---
---
=== Sampal Output ===

Threat Report
[!] Brute-force detected from 192.168.0.2 (5 failed attempts)
[!] SQL Injection attempt from 192.168.0.4: GET /login?user=' OR 1=1 --
[!] XSS attempt from 192.168.0.3: GET /search?q=<script>alert('x')</script>

[✓] Analysis complete.
→ Brute-force IPs: 1
→ SQLi Attempts: 1
→ XSS Attempts: 1


