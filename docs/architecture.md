# PhishGuard AI System Architecture

## System Overview

PhishGuard AI employs a multi-tiered, defensive cybersecurity architecture designed to isolate untrusted URL & email inputs, extract lexical and structural features safely, run machine learning predictions, compute transparent risk scores, deliver real-time WebSocket telemetry, export SIEM/STIX 2.1 threat intelligence, dispatch automated webhooks, serve live firewall IOC blocklists, and run continuous security compliance audits.

```
+-------------------------------------------------------------------+
|                     React 18 / Vite Frontend                      |
|      (SOC Dashboard, Batch Scanner, Reports, Admin Console)       |
+---------------------------------+---------------------------------+
                                  | HTTP REST / WebSockets
                                  v
+-------------------------------------------------------------------+
|                        FastAPI Backend                            |
|  - Rate Limiting (Sliding Window HTTP 429)                        |
|  - Auth (JWT & X-API-Key Lifecycle)                               |
|  - Security Headers (HSTS, X-Frame-Options, OWASP Compliance)    |
|  - WebSockets Telemetry Alert Stream (/ws/alerts)                |
+---------------------------------+---------------------------------+
                                  |
        +-------------------------+-------------------------+
        |                         |                         |
        v                         v                         v
+---------------+       +------------------+      +--------------------+
| ML Engine     |       | Risk Engine      |      | Security Engine    |
| - Scikit-Learn|       | - 0-100 Weighted |      | - SSRF Protection  |
|   Random      |       | - Transparent    |      | - Punycode / IDN   |
|   Forest      |       |   Factors        |      | - Brand Impersonation
| - Retraining  |       | - Recommendation |      | - Email Header SPF |
+---------------+       +------------------+      +--------------------+
        |                         |                         |
        +-------------------------+-------------------------+
                                  |
     +----------------------------+----------------------------+
     |                            |                            |
     v                            v                            v
+------------------+     +------------------+        +-------------------+
| SIEM Exporter    |     | Webhook Engine   |        | Live Threat Feed  |
| - CEF (ArcSight) |     | - HMAC-SHA256    |        | - JSON Feed       |
| - STIX 2.1 JSON  |     | - SOAR / Slack   |        | - Firewall        |
| - Syslog RFC5424 |     |   Dispatch       |        |   Blocklist       |
+------------------+     +------------------+        +-------------------+
                                  |
                                  v
+-------------------------------------------------------------------+
|                   PostgreSQL 16 Database                          |
| - users, scans, url_features, risk_factors, email_scans           |
| - model_versions, api_keys, audit_logs, webhook_subscriptions     |
+-------------------------------------------------------------------+
```

---

## 🔒 Security & SSRF Mitigation Architecture

1. **DNS & IP Validation**: Prior to initiating network connections, target domain IPs are resolved and validated against RFC 1918 private ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), loopback (`127.0.0.0/8`), and link-local cloud metadata addresses (`169.254.169.254`).
2. **Non-Interactive Execution**: Web inspect probes fetch metadata without parsing HTML JavaScript or submitting form payloads.
3. **Strict Network Constraints**: 5-second connection timeouts, maximum 3 multi-hop redirects, and max payload limits.
4. **Parameterized Data Access**: ORM parameter binding via SQLAlchemy prevents SQL injection.
5. **Least-Privilege Role Access**: Endpoints enforce role-based permissions (`USER` vs `ADMIN`).
6. **HMAC-SHA256 Signed Webhooks**: Automated threat notifications sign HTTP payloads with unique secret keys (`X-PhishGuard-Signature`).
7. **Automated Security Compliance Audit**: Continuous OWASP compliance checks (`/api/v1/admin/security-audit`).

---

## 📊 Endpoints & Component Directory

| Endpoint Prefix | Feature Area | Description |
|---|---|---|
| `POST /api/v1/scans/url` | URL Scanner | Single URL lexical extraction & risk scoring |
| `POST /api/v1/scans/batch` | Batch Scanner | Bulk inspection of up to 50 URLs per batch |
| `POST /api/v1/scans/email` | Email Inspector | RFC 822 EML header & body analysis |
| `GET /api/v1/scans/{id}/export/siem` | Threat Intelligence | CEF, STIX 2.1 JSON, Syslog export |
| `GET /api/v1/scans/{id}/export/report` | Threat Brief | Standalone HTML Executive Incident Brief |
| `GET /api/v1/threats/feed` | IOC Feed | JSON & Plaintext domain blocklist export |
| `POST /api/v1/webhooks` | Webhook Alerts | Webhook registration for SOAR / Slack dispatch |
| `GET /api/v1/admin/security-audit` | Security Audit | Automated OWASP security compliance audit |
| `POST /api/v1/admin/benchmark` | Performance | Millisecond throughput & latency benchmark |
| `WS /api/v1/ws/alerts` | WebSockets Telemetry | Real-time threat alert broadcast stream |
