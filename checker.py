import re
import ipaddress
from urllib.parse import urlparse

SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "secure", "account", "update",
    "banking", "password", "wallet", "confirm", "suspend", "billing",
]

SUSPICIOUS_TLDS = [
    ".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".gq",
    ".click", ".zip", ".work", ".buzz", ".rest",
]

URL_SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly", "cutt.ly"]

BRANDS = {
    "paypal": "paypal.com",
    "google": "google.com",
    "microsoft": "microsoft.com",
    "amazon": "amazon.com",
    "apple": "apple.com",
    "facebook": "facebook.com",
    "instagram": "instagram.com",
    "netflix": "netflix.com",
    "hdfc": "hdfcbank.com",
    "sbi": "sbi.co.in",
}

HASH_LENGTHS = {32: "MD5", 40: "SHA-1", 64: "SHA-256"}


def detect_ioc_type(value):
    value = value.strip()

    try:
        ipaddress.ip_address(value)
        return "ip"
    except ValueError:
        pass

    if re.fullmatch(r"[a-fA-F0-9]+", value) and len(value) in HASH_LENGTHS:
        return "hash"

    return "url"


def get_verdict(score):
    if score >= 60:
        return "HIGH RISK"
    if score >= 30:
        return "SUSPICIOUS"
    return "LOW RISK"


def analyze_url(raw_url):
    url = raw_url.strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "http://" + url

    findings = []
    score = 0

    try:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
    except ValueError:
        return {
            "type": "url",
            "value": raw_url,
            "score": 100,
            "verdict": "HIGH RISK",
            "findings": ["URL could not be parsed (malformed)"],
        }

    if not host:
        return {
            "type": "url",
            "value": raw_url,
            "score": 0,
            "verdict": "LOW RISK",
            "findings": ["No valid hostname found"],
        }

    # 1. IP address used instead of domain name
    try:
        ipaddress.ip_address(host)
        score += 30
        findings.append("Uses an IP address instead of a domain name (+30)")
    except ValueError:
        pass

    # 2. '@' symbol in URL
    if "@" in url:
        score += 20
        findings.append("Contains '@' symbol, can hide the real destination (+20)")

    # 3. Not using HTTPS
    if parsed.scheme != "https":
        score += 10
        findings.append("Does not use HTTPS (+10)")

    # 4. Very long URL
    if len(url) > 75:
        score += 10
        findings.append(f"Very long URL ({len(url)} characters) (+10)")

    # 5. Too many subdomains
    if host.count(".") > 3:
        score += 15
        findings.append("Too many subdomains (+15)")

    # 6. Many hyphens in domain
    if host.count("-") >= 2:
        score += 10
        findings.append("Multiple hyphens in domain name (+10)")

    # 7. Suspicious TLD
    for tld in SUSPICIOUS_TLDS:
        if host.endswith(tld):
            score += 15
            findings.append(f"Suspicious top-level domain '{tld}' (+15)")
            break

    # 8. Punycode (look-alike characters)
    if "xn--" in host:
        score += 20
        findings.append("Punycode domain, may use look-alike characters (+20)")

    # 9. URL shortener
    if host in URL_SHORTENERS:
        score += 15
        findings.append("URL shortener hides the real destination (+15)")

    # 10. Non-standard port
    try:
        if parsed.port and parsed.port not in (80, 443):
            score += 10
            findings.append(f"Non-standard port {parsed.port} (+10)")
    except ValueError:
        score += 10
        findings.append("Invalid port number (+10)")

    # 11. Suspicious keywords
    found = [k for k in SUSPICIOUS_KEYWORDS if k in url.lower()]
    if found:
        points = min(len(found) * 8, 24)
        score += points
        findings.append(f"Suspicious keywords: {', '.join(found)} (+{points})")

    # 12. Brand impersonation
    for brand, real_domain in BRANDS.items():
        if brand in host and not (host == real_domain or host.endswith("." + real_domain)):
            score += 25
            findings.append(f"Possible '{brand}' impersonation, real domain is {real_domain} (+25)")
            break

    score = min(score, 100)
    if not findings:
        findings.append("No suspicious patterns found in URL structure")

    return {
        "type": "url",
        "value": raw_url,
        "score": score,
        "verdict": get_verdict(score),
        "findings": findings,
    }


def analyze(value):
    value = value.strip()
    kind = detect_ioc_type(value)

    if kind == "url":
        return analyze_url(value)

    if kind == "ip":
        label = "Private IP" if ipaddress.ip_address(value).is_private else "Public IP"
        return {
            "type": "ip",
            "value": value,
            "score": 0,
            "verdict": "NOT CHECKED YET",
            "findings": [f"{label}. Reputation lookup will be added in the next step"],
        }

    return {
        "type": "hash",
        "value": value,
        "score": 0,
        "verdict": "NOT CHECKED YET",
        "findings": [f"{HASH_LENGTHS[len(value)]} hash. Reputation lookup will be added in the next step"],
    }


if __name__ == "__main__":
    tests = [
        "https://www.google.com",
        "http://paypal.com.secure-login.verify-account.xyz/signin",
        "http://192.168.1.5/login",
        "https://bit.ly/abc123",
        "8.8.8.8",
        "44d88612fea8a8f36de82e1278abb02f",
    ]

    for t in tests:
        r = analyze(t)
        print(f"[{r['verdict']}] ({r['type']}) score={r['score']} | {r['value']}")
        for f in r["findings"]:
            print("   -", f)
        print()