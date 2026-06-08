#!/usr/bin/env python3
"""
Real IP Finder - OSINT Tool
For use only on domains you own or have explicit authorization to test.
"""

import socket
import ssl
import json
import urllib.request
import urllib.parse
import subprocess
import sys

# ── optional deps (install if available) ────────────────────────────────────
try:
    import dns.resolver
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


def banner():
    print("=" * 55)
    print("         Real IP Finder - OSINT Recon Tool")
    print("   Use only on domains you own / are authorized to test")
    print("=" * 55)


# ── 1. Basic DNS resolution ──────────────────────────────────────────────────
def basic_dns(domain):
    print("\n[1] Basic DNS Resolution")
    try:
        ips = socket.getaddrinfo(domain, None)
        seen = set()
        for item in ips:
            ip = item[4][0]
            if ip not in seen:
                seen.add(ip)
                print(f"    {ip}")
    except Exception as e:
        print(f"    Error: {e}")


# ── 2. DNS record lookup (MX, TXT, NS) ──────────────────────────────────────
def dns_records(domain):
    print("\n[2] DNS Records (MX / TXT / NS)")
    if HAS_DNSPYTHON:
        for rtype in ("MX", "TXT", "NS", "A", "AAAA"):
            try:
                answers = dns.resolver.resolve(domain, rtype)
                for r in answers:
                    print(f"    {rtype:6} {r}")
            except Exception:
                pass
    else:
        # Fallback: use system dig/nslookup
        for rtype in ("MX", "TXT", "NS", "A"):
            try:
                result = subprocess.run(
                    ["dig", "+short", rtype, domain],
                    capture_output=True, text=True, timeout=5
                )
                if result.stdout.strip():
                    for line in result.stdout.strip().splitlines():
                        print(f"    {rtype:6} {line}")
            except FileNotFoundError:
                print("    dig not found; install dnspython: pip install dnspython")
                break
            except Exception as e:
                print(f"    {e}")


# ── 3. Common subdomains ─────────────────────────────────────────────────────
COMMON_SUBS = [
    "mail", "smtp", "ftp", "direct", "origin", "cpanel",
    "webmail", "api", "dev", "staging", "beta", "admin",
    "remote", "vpn", "ns1", "ns2", "mx", "blog", "shop",
]

def subdomain_scan(domain):
    print("\n[3] Common Subdomain IP Scan")
    found = {}
    for sub in COMMON_SUBS:
        fqdn = f"{sub}.{domain}"
        try:
            ip = socket.gethostbyname(fqdn)
            print(f"    {fqdn:40} -> {ip}")
            found[fqdn] = ip
        except socket.gaierror:
            pass
    if not found:
        print("    No common subdomains resolved.")
    return found


# ── 4. HTTP header inspection ────────────────────────────────────────────────
def http_headers(domain):
    print("\n[4] HTTP Response Headers")
    interesting = {
        "x-real-ip", "x-forwarded-for", "x-originating-ip",
        "x-powered-by", "server", "x-backend", "via",
        "x-origin", "cf-ray", "x-amz-cf-id",
    }
    try:
        url = f"https://{domain}"
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        ctx = ssl.create_default_context()
        with urllib.request.urlopen(req, context=ctx, timeout=8) as resp:
            for k, v in resp.headers.items():
                if k.lower() in interesting:
                    print(f"    {k}: {v}")
    except Exception as e:
        print(f"    Error: {e}")


# ── 5. SSL certificate info ──────────────────────────────────────────────────
def ssl_cert(domain):
    print("\n[5] SSL Certificate Subject / SANs")
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(
            socket.create_connection((domain, 443), timeout=6),
            server_hostname=domain
        ) as s:
            cert = s.getpeercert()
            subj = dict(x[0] for x in cert.get("subject", []))
            print(f"    CN : {subj.get('commonName', 'N/A')}")
            print(f"    Org: {subj.get('organizationName', 'N/A')}")
            sans = cert.get("subjectAltName", [])
            dns_sans = [v for t, v in sans if t == "DNS"]
            if dns_sans:
                print(f"    SANs ({len(dns_sans)}): {', '.join(dns_sans[:10])}")
    except Exception as e:
        print(f"    Error: {e}")


# ── 6. crt.sh certificate transparency ──────────────────────────────────────
def crtsh_lookup(domain):
    print("\n[6] crt.sh Certificate Transparency")
    try:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
        names = set()
        for entry in data:
            for name in entry.get("name_value", "").splitlines():
                name = name.strip().lstrip("*.")
                if name and domain in name:
                    names.add(name)
        print(f"    Found {len(names)} unique names from CT logs:")
        for n in sorted(names)[:20]:
            print(f"      {n}")
        if len(names) > 20:
            print(f"      ... and {len(names)-20} more")
    except Exception as e:
        print(f"    Error: {e}")


# ── 7. SPF record IP extraction ──────────────────────────────────────────────
def spf_ips(domain):
    print("\n[7] SPF Record IP Extraction")
    if HAS_DNSPYTHON:
        try:
            answers = dns.resolver.resolve(domain, "TXT")
            for r in answers:
                txt = r.to_text().strip('"')
                if "v=spf1" in txt:
                    print(f"    SPF: {txt}")
                    parts = txt.split()
                    for p in parts:
                        if p.startswith("ip4:") or p.startswith("ip6:"):
                            print(f"    IP found: {p.split(':',1)[1]}")
        except Exception as e:
            print(f"    Error: {e}")
    else:
        print("    Install dnspython for SPF parsing: pip install dnspython")


# ── 8. Shodan hint ──────────────────────────────────────────────────────────
def shodan_hint(domain):
    print("\n[8] Shodan Search Hint")
    print(f"    Search manually on https://www.shodan.io/")
    print(f"    Queries to try:")
    print(f'      hostname:"{domain}"')
    print(f'      ssl.cert.subject.cn:"{domain}"')
    print(f"    Or use the Shodan CLI: shodan search hostname:{domain}")


# ── Main ─────────────────────────────────────────────────────────────────────
def main():
    banner()
    if len(sys.argv) > 1:
        domain = sys.argv[1].strip().lstrip("https://").lstrip("http://").rstrip("/")
    else:
        domain = input("\nEnter domain (e.g. example.com): ").strip()
        domain = domain.lstrip("https://").lstrip("http://").rstrip("/")

    print(f"\nTarget: {domain}")

    basic_dns(domain)
    dns_records(domain)
    subdomain_scan(domain)
    http_headers(domain)
    ssl_cert(domain)
    crtsh_lookup(domain)
    spf_ips(domain)
    shodan_hint(domain)

    print("\n" + "=" * 55)
    print("Done. Cross-reference IPs with DNS history tools like")
    print("SecurityTrails or ViewDNS.info for historical records.")
    print("=" * 55)


if __name__ == "__main__":
    main()
