from typing import Tuple, Optional

# Verified Legitimate Top Domains Whitelist (prevents false positive alerts on official domains)
LEGITIMATE_TOP_DOMAINS = {
    "google.com", "www.google.com", "accounts.google.com",
    "microsoft.com", "login.microsoftonline.com", "account.microsoft.com", "live.com",
    "paypal.com", "www.paypal.com",
    "github.com", "www.github.com", "api.github.com",
    "apple.com", "idmsa.apple.com",
    "amazon.com", "www.amazon.com",
    "facebook.com", "www.facebook.com",
    "linkedin.com", "www.linkedin.com",
    "twitter.com", "x.com",
    "stripe.com", "dashboard.stripe.com"
}

def check_domain_whitelist(domain: str) -> Tuple[bool, Optional[str]]:
    """
    Checks if a target domain is a verified legitimate official domain.
    Returns (is_whitelisted, brand_name).
    """
    clean_domain = domain.lower().strip()

    if clean_domain in LEGITIMATE_TOP_DOMAINS:
        if "paypal" in clean_domain:
            return True, "PayPal Official"
        if "microsoft" in clean_domain:
            return True, "Microsoft Official"
        if "google" in clean_domain:
            return True, "Google Official"
        if "github" in clean_domain:
            return True, "GitHub Official"
        if "apple" in clean_domain:
            return True, "Apple Official"
        return True, "Verified Legitimate Domain"

    return False, None
