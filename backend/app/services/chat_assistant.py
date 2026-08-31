from typing import Dict, Any, List

def analyze_threat_query_with_guard_ai(query: str, scan_context: Dict[str, Any] = None) -> Dict[str, Any]:
    """
    Simulates AI SOC Security Analyst reasoning for threat queries and scan probe findings.
    Returns structured analysis, threat breakdown, protocol policies, and SOC mitigation playbooks.
    """
    q_lower = query.lower()

    target_domain = scan_context.get("domain", "") if scan_context else ""
    risk_score = scan_context.get("risk_score", 0) if scan_context else 0
    classification = scan_context.get("classification", "UNKNOWN") if scan_context else "UNKNOWN"

    playbook: List[str] = []
    response_text = ""

    if "phishing" in q_lower or "fake" in q_lower or "spoof" in q_lower or risk_score >= 60:
        response_text = (
            f"GuardAI Assessment for target domain '{target_domain or 'queried asset'}': "
            "High risk phishing indicators identified. The target displays characteristic brand impersonation, "
            "unusual TLD usage, or structural lexical anomalies. Immediate perimeter action recommended."
        )
        playbook = [
            "1. Block domain and associated IP ranges on perimeter firewalls and DNS resolvers.",
            "2. Initiate credential reset for users who accessed this domain in the past 24 hours.",
            "3. Export scan findings in CEF/STIX 2.1 format to centralized SIEM cluster.",
            "4. Submit domain to browser blocklists (Google Safe Browsing, Microsoft SmartScreen)."
        ]
    elif "ssrf" in q_lower or "ip" in q_lower or "internal" in q_lower:
        response_text = (
            "GuardAI SSRF Mitigation Guide: PhishGuard AI enforces RFC 1918 private range blocklists "
            "(10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) and blocks cloud metadata endpoints (169.254.169.254). "
            "Ensure internal applications apply strict DNS resolution verification before fetching remote URLs."
        )
        playbook = [
            "1. Enforce outbound HTTP proxying with URL whitelist filtering.",
            "2. Block loopback (127.0.0.1) and link-local metadata addresses at network layer.",
            "3. Reject HTTP redirects targeting internal network subnets."
        ]
    elif "email" in q_lower or "header" in q_lower or "spf" in q_lower:
        response_text = (
            "GuardAI Email Security Inspector: Evaluates RFC 822 email headers for SPF, DKIM, and DMARC alignment. "
            "Reply-To mismatches are high-priority indicators of business email compromise (BEC) or phishing impersonation."
        )
        playbook = [
            "1. Inspect Authentication-Results header for SPF/DKIM validation failures.",
            "2. Verify Reply-To header matches From header domain exactly.",
            "3. Quarantine emails containing external links targeting suspicious TLDs."
        ]
    else:
        response_text = (
            f"GuardAI SOC Assistant: Analyzed query '{query}'. PhishGuard AI employs multi-layered lexical feature extraction, "
            "Scikit-Learn Random Forest machine learning models, and transparent 0-100 risk scoring to evaluate security threats."
        )
        playbook = [
            "1. Submit target URL or EML email file for automated risk scoring.",
            "2. Review extracted telemetry features and brand impersonation warnings.",
            "3. Utilize automated webhooks for real-time alert dispatch to SOAR platforms."
        ]

    return {
        "query": query,
        "response": response_text,
        "mitigation_playbook": playbook,
        "suggested_actions": [
            "Export Executive Threat Report (HTML)",
            "Generate SIEM CEF/STIX 2.1 Threat Indicator",
            "Configure Automated Threat Webhook"
        ],
        "model_version": "GuardAI-SOC-v2.5"
    }
