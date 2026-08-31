import json
from datetime import datetime, timezone

def export_scan_as_cef(scan_data: dict) -> str:
    """
    Formats a scan report into Common Event Format (CEF) for SIEM systems (ArcSight, Splunk, QRadar).
    Format: CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
    """
    severity_num = 1
    score = scan_data.get("risk_score", 0)
    if score >= 80: severity_num = 10
    elif score >= 60: severity_num = 7
    elif score >= 40: severity_num = 5
    elif score >= 20: severity_num = 3

    cef_str = (
        f"CEF:0|PhishGuardAI|DefensePlatform|1.0|PHISH_DETECT|Phishing Risk Audit|{severity_num}|"
        f"request={scan_data.get('url')} "
        f"requestDomain={scan_data.get('domain')} "
        f"cn1={score} cn1Label=RiskScore "
        f"cat={scan_data.get('classification')} "
        f"flexString1={scan_data.get('ml_probability')} flexString1Label=MLProbability"
    )
    return cef_str

def export_scan_as_stix(scan_data: dict) -> dict:
    """
    Formats a scan report into STIX 2.1 JSON Indicator object for Threat Intelligence Platforms (TIP).
    """
    stix_indicator = {
        "type": "bundle",
        "id": f"bundle--{scan_data.get('id')}",
        "spec_version": "2.1",
        "objects": [
            {
                "type": "indicator",
                "spec_version": "2.1",
                "id": f"indicator--{scan_data.get('id')}",
                "created": datetime.now(timezone.utc).isoformat(),
                "modified": datetime.now(timezone.utc).isoformat(),
                "name": f"Phishing Threat Indicator: {scan_data.get('domain')}",
                "description": f"PhishGuard AI Risk Analysis Score {scan_data.get('risk_score')}/100. Classification: {scan_data.get('classification')}.",
                "indicator_types": ["malicious-activity", "phishing"],
                "pattern": f"[url:value = '{scan_data.get('url')}']",
                "pattern_type": "stix",
                "valid_from": datetime.now(timezone.utc).isoformat(),
                "confidence": int((scan_data.get('ml_probability', 0.5) * 100))
            }
        ]
    }
    return stix_indicator

def export_scan_as_syslog(scan_data: dict) -> str:
    """
    Formats a scan report into Syslog RFC 5424 structured event string.
    """
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    syslog_msg = (
        f"<134>1 {timestamp} phishguard-soc phishguard-ai {scan_data.get('id')} - - "
        f"[phish@4712 domain=\"{scan_data.get('domain')}\" score=\"{scan_data.get('risk_score')}\" "
        f"classification=\"{scan_data.get('classification')}\"] Threat analysis completed for {scan_data.get('url')}"
    )
    return syslog_msg
