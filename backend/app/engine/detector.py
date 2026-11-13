import math
import re
import urllib.parse
from typing import Dict, Any, List

# Target brand names frequently targeted by spear-phishing
TARGET_BRANDS = [
    "paypal", "apple", "microsoft", "google", "netflix",
    "amazon", "chase", "wellsfargo", "binance", "coinbase", "facebook", "bankofamerica"
]

# High abuse TLDs according to Spamhaus / APWG reports
HIGH_RISK_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "click", "buzz", "club", "work", "loan", "support", "vip"
}

# Credential harvesting trigger words
CREDENTIAL_KEYWORDS = [
    "login", "signin", "verify", "account", "banking", "password",
    "update", "wallet", "recover", "authenticate", "confirm", "security", "checkout"
]

# Common Cyrillic / Greek homoglyphs mimicking Latin letters
CONFUSABLES = {
    '\u0430': 'a', '\u0441': 'c', '\u0435': 'e', '\u043e': 'o',
    '\u0440': 'p', '\u0443': 'y', '\u0445': 'x', '\u0456': 'i',
    '\u0458': 'j', '\u03bf': 'o', '\u03c1': 'p', '\u03b1': 'a'
}

def calculate_shannon_entropy(text: str) -> float:
    """
    Computes Shannon Entropy of character distribution: H = -sum(p * log2(p)).
    Higher values (> 3.8 for domains) indicate DGA generation or token obfuscation.
    """
    if not text:
        return 0.0
    freq = {}
    for char in text:
        freq[char] = freq.get(char, 0) + 1
    length = len(text)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 3)

def detect_homoglyphs(domain: str) -> Dict[str, Any]:
    """
    Detects IDN / Punycode homoglyph spoofing and mixed Cyrillic/Greek confusables.
    """
    has_punycode = "xn--" in domain.lower()
    confusables_found = []

    for char in domain:
        if char in CONFUSABLES:
            confusables_found.append({
                "char": char,
                "unicode": f"U+{ord(char):04X}",
                "mimics": CONFUSABLES[char]
            })

    # Test decoded IDN if punycode
    decoded_domain = domain
    if has_punycode:
        try:
            decoded_domain = domain.encode("ascii").decode("idna")
            for char in decoded_domain:
                if char in CONFUSABLES and not any(c["char"] == char for c in confusables_found):
                    confusables_found.append({
                        "char": char,
                        "unicode": f"U+{ord(char):04X}",
                        "mimics": CONFUSABLES[char]
                    })
        except Exception:
            pass

    return {
        "has_punycode": has_punycode,
        "confusables_found": confusables_found,
        "is_spoofed": has_punycode or len(confusables_found) > 0,
        "decoded_domain": decoded_domain
    }

def analyze_url(raw_url: str) -> Dict[str, Any]:
    """
    Performs comprehensive lexical, structural, and heuristic risk assessment of a URL.
    """
    url = raw_url.strip()
    if not (url.startswith("http://") or url.startswith("https://")):
        url = "http://" + url

    parsed = urllib.parse.urlparse(url)
    hostname = (parsed.hostname or "").lower()
    path = parsed.path.lower()
    query = parsed.query.lower()
    full_path_query = path + ("?" + query if query else "")

    risk_factors = []
    score = 0.0

    # 1. IP Address Hostname
    ip_pattern = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
    if ip_pattern.match(hostname):
        score += 35.0
        risk_factors.append({
            "rule": "IP_ADDRESS_HOST",
            "weight": 35.0,
            "description": f"Target host uses raw numeric IP '{hostname}' instead of a registered domain name."
        })

    # 2. Homoglyph / Punycode Spoofing
    homoglyph_data = detect_homoglyphs(hostname)
    if homoglyph_data["is_spoofed"]:
        score += 45.0
        conf_summary = ", ".join([f"{c['char']} ({c['unicode']} -> {c['mimics']})" for c in homoglyph_data["confusables_found"][:3]])
        risk_factors.append({
            "rule": "HOMOGLYPH_IDN_SPOOF",
            "weight": 45.0,
            "description": f"Domain contains Internationalized Domain Name (IDN) or confusable glyphs mimicking legitimate characters: {conf_summary}"
        })

    # 3. Brand Impersonation / Typosquatting
    matched_brand = None
    for brand in TARGET_BRANDS:
        if brand in hostname:
            parts = hostname.split(".")
            # If the base domain is not the genuine brand domain
            if not (len(parts) >= 2 and parts[-2] == brand):
                matched_brand = brand
                score += 35.0
                risk_factors.append({
                    "rule": "BRAND_IMPERSONATION",
                    "weight": 35.0,
                    "description": f"Domain hostname contains trusted brand keyword '{brand}' but is not an authorized domain."
                })
                break

    # 4. High Risk / Abuse TLD
    tld = hostname.split(".")[-1] if "." in hostname else ""
    if tld in HIGH_RISK_TLDS:
        score += 20.0
        risk_factors.append({
            "rule": "HIGH_RISK_TLD",
            "weight": 20.0,
            "description": f"Top-level domain '.{tld}' is recognized for high abuse/malicious campaign prevalence."
        })

    # 5. Shannon Entropy (Random / DGA Detection)
    # Check domain name minus TLD
    domain_body = hostname.rsplit(".", 1)[0] if "." in hostname else hostname
    domain_entropy = calculate_shannon_entropy(domain_body)
    if domain_entropy >= 3.8 and len(domain_body) >= 10:
        score += 20.0
        risk_factors.append({
            "rule": "HIGH_DOMAIN_ENTROPY",
            "weight": 20.0,
            "description": f"Domain body entropy is elevated ({domain_entropy:.2f} bits/symbol), indicating possible algorithmic generation (DGA) or obfuscation."
        })

    # 6. Credential Harvesting Indicators in Path / Query
    found_keywords = [kw for kw in CREDENTIAL_KEYWORDS if kw in full_path_query]
    if found_keywords:
        kw_score = min(25.0, len(found_keywords) * 10.0)
        score += kw_score
        risk_factors.append({
            "rule": "CREDENTIAL_HARVESTING_PATH",
            "weight": kw_score,
            "description": f"Path and query parameters contain authentication/credential harvesting terminology: {', '.join(found_keywords[:4])}."
        })

    # 7. Subdomain Depth & Hyphens
    subdomains = hostname.split(".")
    if len(subdomains) > 4:
        score += 15.0
        risk_factors.append({
            "rule": "EXCESSIVE_SUBDOMAINS",
            "weight": 15.0,
            "description": f"Hostname exhibits suspicious subdomain nesting depth ({len(subdomains)} levels)."
        })

    hyphen_count = hostname.count("-")
    if hyphen_count >= 2:
        score += 10.0
        risk_factors.append({
            "rule": "EXCESSIVE_HYPHENS",
            "weight": 10.0,
            "description": f"Hostname uses multiple hyphens ({hyphen_count}) commonly seen in typosquatting lures."
        })

    # 8. User Info / '@' Deception
    if "@" in raw_url:
        score += 25.0
        risk_factors.append({
            "rule": "AUTHORITY_DECEPTION_AT_SYMBOL",
            "weight": 25.0,
            "description": "URL includes '@' character to mislead visual inspection away from actual destination host."
        })

    # 9. Excessive Length
    if len(raw_url) > 100:
        score += 10.0
        risk_factors.append({
            "rule": "SUSPICIOUS_URL_LENGTH",
            "weight": 10.0,
            "description": f"Total URL length ({len(raw_url)} chars) exceeds standard web navigation lengths."
        })

    # Final bounded score
    threat_score = round(min(100.0, max(0.0, score)), 1)

    # Classification Tier
    if threat_score < 25.0:
        classification = "BENIGN"
    elif 25.0 <= threat_score <= 65.0:
        classification = "SUSPICIOUS"
    else:
        classification = "MALICIOUS"

    return {
        "url": raw_url,
        "normalized_url": url,
        "hostname": hostname,
        "tld": tld,
        "threat_score": threat_score,
        "classification": classification,
        "domain_entropy": domain_entropy,
        "url_length": len(raw_url),
        "homoglyph_analysis": homoglyph_data,
        "risk_factors": risk_factors
    }
