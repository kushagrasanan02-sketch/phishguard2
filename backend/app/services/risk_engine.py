from typing import Dict, Any, List, Tuple
from app.services.ml_engine import predict_phishing_probability
from app.services.threat_feed import check_domain_whitelist

def calculate_risk_score(features: Dict[str, Any]) -> Tuple[int, str, float, List[Dict[str, Any]], List[str], str]:
    """
    Computes a transparent weighted risk score (0-100), classification, ML probability estimate,
    contributing risk factors list, positive signals list, and recommended security action.
    """
    domain = features.get("domain") or ""
    is_whitelisted, brand_name = check_domain_whitelist(domain)

    if is_whitelisted:
        return 0, "SAFE", 0.01, [], [f"Verified Official Domain ({brand_name})", "HTTPS Protocol Enforced"], "Target domain is a verified legitimate official platform."

    score = 0
    risk_factors: List[Dict[str, Any]] = []
    positive_signals: List[str] = []

    # 1. IP Address Target Check (+35)
    if features.get("has_ip"):
        score += 35
        risk_factors.append({
            "factor": "IP Address Target Host",
            "description": "Target hostname uses a raw IP address instead of a domain name.",
            "severity": "CRITICAL",
            "score_contribution": 35
        })

    # 2. Brand Impersonation Detection (+25)
    brand = features.get("brand_impersonated")
    if brand:
        score += 25
        risk_factors.append({
            "factor": "Brand Impersonation Warning",
            "description": f"Potential spoofing or typo-squatting targeting protected brand '{brand}'.",
            "severity": "HIGH",
            "score_contribution": 25
        })

    # 3. Punycode IDN Hostname (+20)
    if features.get("has_punycode"):
        score += 20
        risk_factors.append({
            "factor": "Punycode IDN Encoding",
            "description": "Hostname uses 'xn--' punycode, a technique frequently used in homoglyph attacks.",
            "severity": "HIGH",
            "score_contribution": 20
        })

    # 4. At Symbol Presence (+20)
    if features.get("has_at_symbol"):
        score += 20
        risk_factors.append({
            "factor": "URL Embedded Credential Symbol (@)",
            "description": "URL contains an '@' character, which can obscure the true target destination.",
            "severity": "HIGH",
            "score_contribution": 20
        })

    # 5. Suspicious Keywords Presence (+15)
    keywords = features.get("detected_keywords", [])
    if keywords:
        score += 15
        kw_str = ", ".join(keywords[:5])
        risk_factors.append({
            "factor": "Suspicious Category Keywords",
            "description": f"Detected phishing/authentication triggers: [{kw_str}].",
            "severity": "MEDIUM",
            "score_contribution": 15
        })

    # 6. High-Risk TLD (+15)
    if features.get("unusual_tld"):
        score += 15
        risk_factors.append({
            "factor": "High-Risk Top Level Domain",
            "description": "Domain uses a TLD with high historical correlation to phishing campaigns.",
            "severity": "MEDIUM",
            "score_contribution": 15
        })

    # 7. Excessive Subdomain Depth (+15)
    sub_count = features.get("subdomain_count", 0)
    if sub_count >= 3:
        score += 15
        risk_factors.append({
            "factor": "Excessive Subdomain Depth",
            "description": f"Target contains {sub_count} subdomain levels, often used to disguise malicious paths.",
            "severity": "MEDIUM",
            "score_contribution": 15
        })

    # 8. Excessive URL Length (+10)
    url_len = features.get("url_length", 0)
    if url_len > 75:
        score += 10
        risk_factors.append({
            "factor": "Excessive URL Length",
            "description": f"Unusually long URL structure ({url_len} characters).",
            "severity": "LOW",
            "score_contribution": 10
        })

    # 9. Non-HTTPS Unencrypted Protocol (+10)
    if not features.get("https_enabled"):
        score += 10
        risk_factors.append({
            "factor": "Unencrypted HTTP Connection",
            "description": "Target site does not enforce HTTPS encryption.",
            "severity": "MEDIUM",
            "score_contribution": 10
        })
    else:
        positive_signals.append("HTTPS Protocol Enforced")

    if not features.get("has_ip") and not features.get("has_punycode"):
        positive_signals.append("Standard ASCII Domain Formatting")

    if sub_count < 2:
        positive_signals.append("Normal Subdomain Depth")

    # Predict probability via trained Scikit-Learn Random Forest model
    ml_probability = predict_phishing_probability(features)

    # Ensemble Weighted Score: 60% Rule-Based Score + 40% ML Model Probability Score
    ensemble_score = int(min(100, round((score * 0.60) + (ml_probability * 100.0 * 0.40))))

    # Classification Mapping
    if ensemble_score >= 75:
        classification = "PHISHING"
        recommendation = "Do NOT visit or enter credentials. Target displays multiple high-severity phishing indicators."
    elif ensemble_score >= 50:
        classification = "SUSPICIOUS"
        recommendation = "High phishing risk detected. Exercise extreme caution and independently verify the domain before interacting."
    elif ensemble_score >= 25:
        classification = "GUARDED"
        recommendation = "Guarded risk profile. Review highlighted telemetry indicators prior to submitting sensitive information."
    else:
        classification = "SAFE"
        recommendation = "Low threat probability. Structural indicators match clean, standard web patterns."

    return ensemble_score, classification, ml_probability, risk_factors, positive_signals, recommendation
