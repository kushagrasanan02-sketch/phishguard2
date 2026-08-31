import re
import ipaddress
from urllib.parse import urlparse, parse_qs
from typing import Dict, Any, List, Optional

# Configurable Suspicious Keywords by Security Category
SUSPICIOUS_KEYWORDS = {
    "authentication": ["login", "signin", "sign-in", "verify", "verification", "account", "password", "credential", "auth", "security-update", "confirm-identity"],
    "financial": ["bank", "payment", "invoice", "billing", "wallet", "paypal", "crypto", "transfer", "checkout", "card", "banking"],
    "urgency": ["urgent", "suspended", "expired", "verify-now", "action-required", "lock", "restricted", "alert", "security-notice"]
}

# High-Risk / Frequently Abused TLDs in Phishing Campaigns
HIGH_RISK_TLDS = {
    ".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".gq", ".work", ".click", 
    ".zip", ".mov", ".fit", ".country", ".kim", ".science", ".link", ".rest", ".buzz"
}

# Protected Brand List for Impersonation Checks
PROTECTED_BRANDS = [
    "paypal", "microsoft", "google", "amazon", "apple", "netflix", 
    "facebook", "instagram", "chase", "wellsfargo", "bankofamerica", 
    "binance", "coinbase", "stripe", "dropbox", "docusign"
]

def extract_url_features(url_str: str, scheme: str, hostname: str) -> Dict[str, Any]:
    """
    Extracts security telemetry and lexical feature vectors from a normalized URL.
    """
    parsed = urlparse(url_str)
    path_and_query = f"{parsed.path}?{parsed.query}" if parsed.query else parsed.path

    # 1. Lexical Length Telemetry
    url_length = len(url_str)
    hostname_length = len(hostname)
    dot_count = url_str.count(".")
    hyphen_count = url_str.count("-")

    # 2. Special Characters Count (@, ?, =, %, _, ~, etc.)
    special_chars = set("@?=%_~!$&'()*+,;:")
    special_char_count = sum(1 for char in url_str if char in special_chars)

    # 3. Raw IP Target Check
    has_ip = False
    try:
        ipaddress.ip_address(hostname)
        has_ip = True
    except ValueError:
        has_ip = False

    # 4. At Symbol Presence
    has_at_symbol = "@" in url_str

    # 5. Punycode IDN Check (Homoglyph Attack Indicator)
    has_punycode = "xn--" in hostname.lower()

    # 6. Parameter Complexity
    query_params = parse_qs(parsed.query)
    parameter_count = len(query_params)

    # 7. Subdomain Telemetry & Depth
    subdomain_count = 0
    subdomains = []
    if not has_ip:
        parts = hostname.split(".")
        # Ignore TLD and SLD (standard domain.tld has 2 parts)
        if len(parts) > 2:
            subdomains = parts[:-2]
            subdomain_count = len(subdomains)

    # 8. Suspicious Keyword Extraction
    detected_keywords: List[str] = []
    lower_url = url_str.lower()
    for category, keywords in SUSPICIOUS_KEYWORDS.items():
        for kw in keywords:
            if kw in lower_url and kw not in detected_keywords:
                detected_keywords.append(kw)

    has_suspicious_keywords = len(detected_keywords) > 0

    # 9. Brand Impersonation Evaluation (Levenshtein & Pattern Subdomain Matching)
    brand_impersonated = detect_brand_impersonation(hostname, subdomains)

    # 10. TLD Evaluation
    tld = ""
    if "." in hostname and not has_ip:
        tld = f".{hostname.split('.')[-1].lower()}"

    unusual_tld = tld in HIGH_RISK_TLDS

    # 11. HTTPS Availability
    https_enabled = scheme.lower() == "https"

    return {
        "url_length": url_length,
        "hostname_length": hostname_length,
        "subdomain_count": subdomain_count,
        "dot_count": dot_count,
        "hyphen_count": hyphen_count,
        "special_char_count": special_char_count,
        "has_ip": has_ip,
        "has_at_symbol": has_at_symbol,
        "has_punycode": has_punycode,
        "parameter_count": parameter_count,
        "has_suspicious_keywords": has_suspicious_keywords,
        "detected_keywords": detected_keywords,
        "domain_age_days": None, # Will be populated in Phase 3 Domain Analysis module
        "https_enabled": https_enabled,
        "redirect_count": 0,    # Will be populated in Phase 3 Redirect module
        "ssl_valid": None,      # Will be populated in Phase 3 SSL audit module
        "brand_impersonated": brand_impersonated,
        "unusual_tld": unusual_tld,
        "excessive_subdomain_depth": subdomain_count >= 3
    }

def detect_brand_impersonation(hostname: str, subdomains: List[str]) -> Optional[str]:
    """
    Detects potential brand impersonation via typo-squatting, character substitution, or subdomain spoofing.
    """
    hostname_clean = hostname.lower()

    for brand in PROTECTED_BRANDS:
        # Check if brand appears in subdomain or path typo-squatted (e.g. paypa1, micr0soft, g00gle, amaz0n)
        typo_patterns = {
            "paypal": ["paypa1", "pay-pal", "payp4l", "paypal-security", "paypal-login"],
            "microsoft": ["micr0soft", "mcrosoft", "msft-verify", "microsoft-online"],
            "google": ["g00gle", "gogle", "google-drive-security"],
            "amazon": ["amaz0n", "amazn", "amazon-orders-verify"],
            "apple": ["app1e", "apple-id-verify", "icloud-security"]
        }

        # 1. Exact match on subdomains (e.g. paypal.phishing-domain.com)
        if any(sub == brand for sub in subdomains):
            return brand.capitalize()

        # 2. Pattern match in hostname
        if brand in typo_patterns:
            for pattern in typo_patterns[brand]:
                if pattern in hostname_clean:
                    return brand.capitalize()

        # 3. Levenshtein Distance Check for single label domain names
        domain_sld = hostname_clean.split(".")[0] if "." in hostname_clean else hostname_clean
        if len(domain_sld) >= 4 and domain_sld != brand:
            dist = levenshtein_distance(domain_sld, brand)
            if dist == 1: # Single character typo (e.g., paypa1 vs paypal)
                return brand.capitalize()

    return None

def levenshtein_distance(s1: str, s2: str) -> int:
    """Calculates Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row

    return previous_row[-1]
