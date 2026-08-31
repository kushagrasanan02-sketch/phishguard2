import email
from email import policy
from email.parser import BytesParser, Parser
import re
from typing import Dict, Any, List, Tuple
from app.services.url_extractor import extract_url_features
from app.services.risk_engine import calculate_risk_score

def extract_urls_from_text(text: str) -> List[str]:
    """Extract http/https URLs from raw email text or html using regex."""
    url_pattern = r'https?://[^\s<>"\']+|(?:www\.)[^\s<>"\']+'
    raw_urls = re.findall(url_pattern, text)
    cleaned_urls = []
    for u in raw_urls:
        cleaned = u.rstrip('.,;()[]{}')
        if cleaned and cleaned not in cleaned_urls:
            cleaned_urls.append(cleaned)
    return cleaned_urls

def parse_email_headers_and_body(raw_email_str: str) -> Tuple[Dict[str, Any], str]:
    """
    Parse RFC 822 email text string into header dict and extracted body.
    """
    msg = Parser(policy=policy.default).parsestr(raw_email_str)

    headers = {
        "from": msg.get("From", ""),
        "to": msg.get("To", ""),
        "reply_to": msg.get("Reply-To", ""),
        "subject": msg.get("Subject", "(No Subject)"),
        "return_path": msg.get("Return-Path", ""),
        "date": msg.get("Date", ""),
        "auth_results": msg.get("Authentication-Results", ""),
        "received_spf": msg.get("Received-SPF", ""),
        "dkim_signature": msg.get("DKIM-Signature", "")
    }

    # Extract body content (plaintext or HTML)
    body_parts = []
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            if content_type in ["text/plain", "text/html"]:
                try:
                    payload = part.get_content()
                    if payload:
                        body_parts.append(str(payload))
                except Exception:
                    pass
    else:
        try:
            payload = msg.get_content()
            if payload:
                body_parts.append(str(payload))
        except Exception:
            body_parts.append(raw_email_str)

    body_text = "\n".join(body_parts) if body_parts else raw_email_str
    return headers, body_text

def evaluate_email_security(raw_email_str: str) -> Dict[str, Any]:
    """
    Evaluates raw email headers, SPF/DKIM/DMARC authentication, reply-to mismatch,
    urgency triggers, and embedded URL safety.
    """
    headers, body_text = parse_email_headers_and_body(raw_email_str)

    sender = headers["from"]
    reply_to = headers["reply_to"]
    subject = headers["subject"]

    # 1. Reply-To / BEC Spoofing Mismatch Check
    reply_to_mismatch = False
    sender_domain = ""
    reply_domain = ""

    if sender:
        match_sender = re.search(r'@([\w\.-]+)', sender)
        if match_sender:
            sender_domain = match_sender.group(1).lower()

    if reply_to:
        match_reply = re.search(r'@([\w\.-]+)', reply_to)
        if match_reply:
            reply_domain = match_reply.group(1).lower()

    if sender_domain and reply_domain and sender_domain != reply_domain:
        reply_to_mismatch = True

    # 2. SPF / DKIM / DMARC Authentication Parsing
    spf_result = "PASS"
    dkim_result = "PASS"
    dmarc_result = "PASS"

    auth_header = (headers["auth_results"] + " " + headers["received_spf"]).lower()

    if "spf=fail" in auth_header or "spf=softfail" in auth_header or "spf=neutral" in auth_header:
        spf_result = "FAIL"
    elif "spf=pass" in auth_header:
        spf_result = "PASS"
    elif not headers["received_spf"] and not headers["auth_results"]:
        spf_result = "NONE"

    if "dkim=fail" in auth_header:
        dkim_result = "FAIL"
    elif "dkim=pass" in auth_header or headers["dkim_signature"]:
        dkim_result = "PASS"
    elif not headers["dkim_signature"]:
        dkim_result = "NONE"

    if "dmarc=fail" in auth_header or "dmarc=reject" in auth_header or "dmarc=quarantine" in auth_header:
        dmarc_result = "FAIL"
    elif "dmarc=pass" in auth_header:
        dmarc_result = "PASS"

    # 3. Urgency & Suspicious Phishing Triggers in Subject/Body
    urgency_keywords = ["urgent", "account suspended", "verify immediately", "action required", "unauthorized login", "password reset", "invoice due", "security alert", "wire transfer", "payroll update"]
    found_indicators = []

    text_to_check = (subject + " " + body_text).lower()
    for kw in urgency_keywords:
        if kw in text_to_check:
            found_indicators.append(f"Urgency / Phishing Trigger: '{kw}'")

    if reply_to_mismatch:
        found_indicators.append(f"BEC Spoofing Mismatch: From domain ({sender_domain}) differs from Reply-To ({reply_domain})")

    if spf_result == "FAIL":
        found_indicators.append("SPF Authentication Failure")
    if dkim_result == "FAIL":
        found_indicators.append("DKIM Signature Failure")
    if dmarc_result == "FAIL":
        found_indicators.append("DMARC Policy Enforcement Failure")

    # 4. Extract & Analyze Embedded URLs
    extracted_urls = extract_urls_from_text(raw_email_str)
    url_scans = []
    max_url_risk = 0

    for url in extracted_urls[:5]: # Analyze up to top 5 embedded links
        try:
            from app.security.ssrf import normalize_and_validate_url
            norm_url, scheme, hostname = normalize_and_validate_url(url)
            feats = extract_url_features(norm_url, scheme, hostname)
            risk, classif, prob, factors, pos, rec = calculate_risk_score(feats)
            if risk > max_url_risk:
                max_url_risk = risk
            url_scans.append({
                "url": url,
                "domain": hostname,
                "risk_score": risk,
                "classification": classif
            })
            if classif in ["PHISHING", "SUSPICIOUS", "HIGH"]:
                found_indicators.append(f"High-Risk Embedded Link Detected: {hostname} ({risk}/100)")
        except Exception:
            pass

    # 5. Calculate Overall Email Risk Score (0 - 100)
    email_risk_score = 0
    if spf_result == "FAIL": email_risk_score += 20
    if dkim_result == "FAIL": email_risk_score += 20
    if dmarc_result == "FAIL": email_risk_score += 25
    if reply_to_mismatch: email_risk_score += 30
    if len(found_indicators) > 0: email_risk_score += len(found_indicators) * 10
    if max_url_risk > 0: email_risk_score += int(max_url_risk * 0.4)

    email_risk_score = min(100, email_risk_score)

    classification = "SAFE"
    if email_risk_score >= 75:
        classification = "PHISHING"
    elif email_risk_score >= 50:
        classification = "SUSPICIOUS"
    elif email_risk_score >= 25:
        classification = "GUARDED"

    return {
        "sender": sender or "Unknown Sender",
        "recipient": headers["to"] or "Unknown Recipient",
        "subject": subject,
        "risk_score": email_risk_score,
        "classification": classification,
        "spf_result": spf_result,
        "dkim_result": dkim_result,
        "dmarc_result": dmarc_result,
        "reply_to_mismatch": reply_to_mismatch,
        "extracted_urls": extracted_urls,
        "url_scans": url_scans,
        "indicators": found_indicators
    }
