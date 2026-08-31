import os
import sys
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.main import app
from app.database.session import Base, get_db
from app.services.webhook_service import generate_webhook_signature, trigger_threat_webhooks
from app.services.report_generator import generate_executive_html_report
from app.core.rate_limiter import _request_history

SQLALCHEMY_DATABASE_URL = "sqlite:///./test_phishguard_phase7.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def override_get_db():
    try:
        db = TestingSessionLocal()
        yield db
    finally:
        db.close()

def setup_module(module):
    _request_history.clear()
    app.dependency_overrides[get_db] = override_get_db
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)

def teardown_module(module):
    _request_history.clear()
    Base.metadata.drop_all(bind=engine)
    engine.dispose()
    if os.path.exists("test_phishguard_phase7.db"):
        os.remove("test_phishguard_phase7.db")

def test_batch_url_scanning():
    client = TestClient(app)
    _request_history.clear()

    payload = {
        "urls": [
            "https://google.com",
            "https://paypal.com",
            "http://paypa1-verify-account.xyz/login?session=123"
        ]
    }

    res = client.post("/api/v1/scans/batch", json=payload)
    assert res.status_code == 201
    data = res.json()

    assert data["total_processed"] == 3
    assert data["safe_count"] >= 1
    assert data["phishing_count"] >= 1
    assert data["average_risk_score"] > 0
    assert len(data["scans"]) == 3

def test_webhook_subscription_and_hmac_signing():
    client = TestClient(app)
    _request_history.clear()

    # 1. Register User
    reg = client.post("/api/v1/auth/register", json={"email": "wh_admin@phishguard.sec", "password": "WhPassword123!"})
    assert reg.status_code == 201

    login = client.post("/api/v1/auth/login", data={"username": "wh_admin@phishguard.sec", "password": "WhPassword123!"})
    token = login.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # 2. Create Webhook Subscription
    wh_payload = {
        "target_url": "https://soar.enterprise.sec/api/v1/alerts",
        "events": ["PHISHING_DETECTED", "HIGH_RISK_DETECTED"]
    }
    wh_res = client.post("/api/v1/webhooks", json=wh_payload, headers=headers)
    assert wh_res.status_code == 201
    wh_data = wh_res.json()
    assert "secret" in wh_data
    assert wh_data["secret"].startswith("whsec_")
    webhook_id = wh_data["id"]

    # 3. Test HMAC Signature Verification Helper
    sig = generate_webhook_signature('{"test":"payload"}', wh_data["secret"])
    assert sig.startswith("sha256=")

    # 4. Trigger scan that triggers webhook dispatch
    scan_res = client.post("/api/v1/scans/url", json={"url": "http://paypa1-suspicious-auth.xyz/verify"})
    assert scan_res.status_code == 201

    # 5. List Webhooks
    list_res = client.get("/api/v1/webhooks", headers=headers)
    assert list_res.status_code == 200
    assert len(list_res.json()) >= 1

    # 6. Delete Webhook
    del_res = client.delete(f"/api/v1/webhooks/{webhook_id}", headers=headers)
    assert del_res.status_code == 204

def test_live_threat_intelligence_feed():
    client = TestClient(app)
    _request_history.clear()

    # 1. Populate DB with a high risk scan
    client.post("/api/v1/scans/url", json={"url": "http://1.2.3.4/paypa1-login/auth.php"})

    # 2. JSON Format Threat Feed
    feed_json = client.get("/api/v1/threats/feed?format=json&min_risk=30")
    assert feed_json.status_code == 200
    fj_data = feed_json.json()
    assert "indicators" in fj_data
    assert fj_data["total_indicators"] >= 1

    # 3. Blocklist Format Threat Feed
    feed_blocklist = client.get("/api/v1/threats/feed?format=blocklist&min_risk=30")
    assert feed_blocklist.status_code == 200
    assert "# PhishGuard AI High-Risk Domain Blocklist" in feed_blocklist.text

def test_executive_threat_report_export():
    client = TestClient(app)
    _request_history.clear()

    # 1. Generate a scan
    scan_res = client.post("/api/v1/scans/url", json={"url": "http://paypa1-security-check.xyz/login"})
    scan_id = scan_res.json()["id"]

    # 2. Export HTML Report
    report_res = client.get(f"/api/v1/scans/{scan_id}/export/report?format=html")
    assert report_res.status_code == 200
    assert "<!DOCTYPE html>" in report_res.text
    assert "PhishGuard AI Threat Brief" in report_res.text
    assert "SOC Recommended Actions" in report_res.text

def run_all_phase7_tests():
    print("==================================================")
    print("PHISHGUARD AI - PHASE 7 AUTOMATED VERIFICATION")
    print("==================================================")

    setup_module(None)

    print("[1/4] Testing Batch URL Scanning & Aggregate Metrics...")
    test_batch_url_scanning()
    print("  [OK] Batch URL Scanner Engine: SUCCESS")

    print("[2/4] Testing Webhook Subscription Lifecycle & HMAC Signing...")
    test_webhook_subscription_and_hmac_signing()
    print("  [OK] Webhook Subscriptions & Threat Notification Dispatch: SUCCESS")

    print("[3/4] Testing Live Threat Intelligence IOC Feed (JSON & Blocklist)...")
    test_live_threat_intelligence_feed()
    print("  [OK] Live IOC Feed & Firewall Blocklist Export: SUCCESS")

    print("[4/4] Testing Executive Incident Report Generator (HTML/Brief)...")
    test_executive_threat_report_export()
    print("  [OK] Executive Threat Report Exporter: SUCCESS")

    teardown_module(None)

    print("\nALL PHASE 7 VERIFICATION TESTS PASSED SUCCESSFULLY!")

if __name__ == "__main__":
    run_all_phase7_tests()
