from datetime import datetime, timezone
from typing import Dict, Any

def generate_executive_html_report(scan_data: Dict[str, Any]) -> str:
    """
    Generates a high-impact, standalone HTML Executive Threat Incident Report.
    Suitable for CISO briefings, SOC incident response, and compliance archiving.
    """
    url = scan_data.get("url", "N/A")
    domain = scan_data.get("domain", "N/A")
    risk_score = scan_data.get("risk_score", 0)
    classification = scan_data.get("classification", "UNKNOWN")
    ml_prob = scan_data.get("ml_probability", 0.0)
    scan_id = scan_data.get("id", "N/A")
    created_at = scan_data.get("created_at", datetime.now(timezone.utc).isoformat())

    # Risk badge styling
    badge_color = "#10B981" # Green for SAFE
    if risk_score >= 80 or classification in ["PHISHING", "CRITICAL"]:
        badge_color = "#EF4444" # Red
    elif risk_score >= 60 or classification in ["HIGH", "SUSPICIOUS"]:
        badge_color = "#F59E0B" # Amber
    elif risk_score >= 30:
        badge_color = "#3B82F6" # Blue

    risk_factors = scan_data.get("risk_factors", [])
    factors_html = ""
    if risk_factors:
        for rf in risk_factors:
            factors_html += f"""
            <div style="padding: 10px; margin-bottom: 8px; border-left: 4px solid #EF4444; background: #1F2937; border-radius: 4px;">
                <div style="font-weight: bold; color: #F3F4F6;">{rf.get('factor', 'Risk Signal')} <span style="color: #9CA3AF; font-size: 0.85em;">(+{rf.get('score_contribution', 0)} pts)</span></div>
                <div style="color: #D1D5DB; font-size: 0.9em; margin-top: 4px;">{rf.get('description', '')}</div>
            </div>
            """
    else:
        factors_html = "<div style='color: #10B981;'>No anomalous or high-risk signals detected for this asset.</div>"

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>PhishGuard AI — Threat Incident Executive Brief</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #111827; color: #F9FAFB; margin: 0; padding: 40px; }}
        .container {{ max-width: 900px; margin: 0 auto; background: #1E293B; border: 1px solid #334155; border-radius: 12px; padding: 32px; box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.5); }}
        .header {{ display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #334155; padding-bottom: 20px; margin-bottom: 24px; }}
        .title {{ font-size: 24px; font-weight: 700; color: #60A5FA; letter-spacing: -0.5px; }}
        .subtitle {{ font-size: 13px; color: #94A3B8; margin-top: 4px; }}
        .badge {{ background-color: {badge_color}; color: #FFFFFF; font-weight: bold; padding: 8px 16px; border-radius: 9999px; font-size: 14px; text-transform: uppercase; letter-spacing: 1px; }}
        .grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 24px; }}
        .card {{ background: #0F172A; border: 1px solid #1E293B; padding: 16px; border-radius: 8px; }}
        .card-label {{ font-size: 12px; color: #64748B; text-transform: uppercase; letter-spacing: 0.5px; font-weight: 600; }}
        .card-value {{ font-size: 18px; font-weight: 600; color: #F1F5F9; margin-top: 6px; word-break: break-all; }}
        .section-title {{ font-size: 16px; font-weight: 600; color: #38BDF8; margin-top: 24px; margin-bottom: 12px; border-left: 3px solid #38BDF8; padding-left: 8px; }}
        .footer {{ margin-top: 40px; pt-20; border-top: 1px solid #334155; text-align: center; color: #64748B; font-size: 12px; padding-top: 16px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div>
                <div class="title">🛡️ PhishGuard AI Threat Brief</div>
                <div class="subtitle">Automated Security Analysis & SOC Technical Intelligence Report</div>
            </div>
            <div class="badge">{classification} ({risk_score}/100)</div>
        </div>

        <div class="grid">
            <div class="card">
                <div class="card-label">Target URL Probe</div>
                <div class="card-value" style="font-size: 14px; color: #38BDF8;">{url}</div>
            </div>
            <div class="card">
                <div class="card-label">Target Domain / Host</div>
                <div class="card-value">{domain}</div>
            </div>
            <div class="card">
                <div class="card-label">ML Model Probability</div>
                <div class="card-value">{round(ml_prob * 100, 1)}% Confidence</div>
            </div>
            <div class="card">
                <div class="card-label">Scan UUID & Timestamp</div>
                <div class="card-value" style="font-size: 13px; color: #94A3B8;">{scan_id}<br>{created_at}</div>
            </div>
        </div>

        <div class="section-title">Risk Factor Breakdown & Threat Indicators</div>
        {factors_html}

        <div class="section-title">SOC Recommended Actions</div>
        <ul style="color: #CBD5E1; font-size: 14px; line-height: 1.6; padding-left: 20px;">
            <li>{"Block target domain across enterprise perimeter firewalls and DNS resolvers." if risk_score >= 60 else "No active perimeter blocking required."}</li>
            <li>{"Revoke active user sessions and reset credentials if users interacted with this URL." if risk_score >= 60 else "Monitor domain for potential squatting changes."}</li>
            <li>Submit IOC metrics to centralized SIEM / SOAR cluster for threat correlation.</li>
        </ul>

        <div class="footer">
            PhishGuard AI Incident Engine • Generated for Defensive Cybersecurity Research & Operations • Confidential
        </div>
    </div>
</body>
</html>"""
    return html
