# find_real_ip
Here's a Python script for **legitimate OSINT/recon** purposes (researching your own domains or authorized targets): The script uses only **standard library + optional `dnspython`** — no heavy dependencies required. ## How to Use

**Install optional dependency (recommended):**
```bash
pip install dnspython
```

**Run the script:**
```bash
# Pass domain as argument
python find_real_ip.py example.com

# Or run interactively
python find_real_ip.py
```

---

## What Each Module Does

| # | Technique | What it finds |
|---|-----------|--------------|
| 1 | Basic DNS | Current A/AAAA records |
| 2 | DNS Records | MX, TXT, NS, A, AAAA records |
| 3 | Subdomain Scan | IPs from 20+ common subdomains (mail, ftp, origin…) |
| 4 | HTTP Headers | `X-Real-IP`, `X-Forwarded-For`, `Server`, `Via`, etc. |
| 5 | SSL Certificate | CN, Org, Subject Alternative Names |
| 6 | crt.sh CT Logs | Subdomains from certificate transparency history |
| 7 | SPF Record | IPs listed in the domain's SPF email policy |
| 8 | Shodan Hint | Ready-made queries to paste into Shodan |

---

## Sample Output
```
=======================================================
         Real IP Finder - OSINT Recon Tool
=======================================================
Target: example.com

[1] Basic DNS Resolution
    93.184.216.34

[3] Common Subdomain IP Scan
    mail.example.com          -> 198.51.100.5
    origin.example.com        -> 203.0.113.12   ← real origin IP

[5] SSL Certificate
    CN:  example.com
    SANs: www.example.com, mail.example.com

[6] crt.sh Certificate Transparency
    Found 14 unique names from CT logs
```

---

> **Legal reminder:** Only use this on domains you own or have written authorization to test. Unauthorized scanning may violate laws in your country.
