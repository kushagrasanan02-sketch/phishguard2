import os
import sys
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.main import app
from app.database.session import Base, get_db
from app.services.email_parser import evaluate_email_security, parse_email_headers_and_body
from app.services.ml_engine import train_and_persist_model, predict_phishing_probability

SQLALCHEMY_DATABASE_URL = "sqlite:///./test_phishguard_phase3.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def override_get_db():
    try:
        db = TestingSessionLocal()
        yield db
    finally:
        db.close()

def setup_module(module):
    from app.core.rate_limiter import _request_history
    _request_history.clear()
    app.dependency_overrides[get_db] = override_get_db
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)

def teardown_module(module):
    Base.metadata.drop_all(bind=engine)
    engine.dispose()
    if os.path.exists("test_phishguard_phase3.db"):
        os.remove("test_phishguard_phase3.db")

def test_email_security_parsing():
    raw_sample = """From: Security Alert <security@paypa1-verify.xyz>
To: target@victim.com
Reply-To: phisher@hacker.com
Subject: URGENT: Account Suspended Immediately
Authentication-Results: spf=fail (sender IP 1.2.3.4)

Dear customer, your account was compromised. Please verify immediately at http://paypa1-login-verify.xyz/auth?user=test
"""

    headers, body = parse_email_headers_and_body(raw_sample)
    assert "paypa1-verify.xyz" in headers["from"]
    assert "phisher@hacker.com" in headers["reply_to"]

    result = evaluate_email_security(raw_sample)
    assert result["risk_score"] > 50
    assert result["classification"] in ["SUSPICIOUS", "PHISHING"]
    assert result["reply_to_mismatch"] is True
    assert result["spf_result"] == "FAIL"
    assert len(result["extracted_urls"]) >= 1

def test_ml_model_pipeline():
    # 1. Train and save model
    db = TestingSessionLocal()
    train_res = train_and_persist_model(db, "v1.test")
    db.close()

    assert train_res["version"] == "v1.test"
    assert train_res["metrics"]["accuracy"] > 0.85
    assert train_res["metrics"]["precision"] > 0.85

    # 2. Predict test feature probabilities
    clean_feats = {"url_length": 30, "hostname_length": 15, "subdomain_count": 1, "https_enabled": True}
    prob_clean = predict_phishing_probability(clean_feats)
    assert prob_clean < 0.50

    phish_feats = {
        "url_length": 110,
        "hostname_length": 45,
        "subdomain_count": 4,
        "has_ip": True,
        "has_at_symbol": True,
        "has_suspicious_keywords": True,
        "https_enabled": False,
        "brand_impersonated": "PayPal"
    }
    prob_phish = predict_phishing_probability(phish_feats)
    assert prob_phish > 0.50

def test_phase3_api_endpoints():
    client = TestClient(app)

    # 1. Register & Login Admin user
    reg_payload = {
        "email": "admin_phase3@phishguard.sec",
        "password": "AdminPassword123!",
        "full_name": "Phase 3 Lead Security Admin"
    }
    reg_res = client.post("/api/v1/auth/register", json=reg_payload)
    assert reg_res.status_code == 201

    login_res = client.post("/api/v1/auth/login", data={"username": "admin_phase3@phishguard.sec", "password": "AdminPassword123!"})
    token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # 2. POST /api/v1/scans/email (Email Inspection Endpoint)
    email_payload = {
        "raw_email": "From: admin@paypal.com\nReply-To: bad@hacker.com\nSubject: Password Reset\n\nVerify at http://paypa1-sec.xyz"
    }
    email_res = client.post("/api/v1/scans/email", json=email_payload, headers=headers)
    assert email_res.status_code == 201
    e_data = email_res.json()
    assert e_data["reply_to_mismatch"] is True
    assert e_data["risk_score"] > 30

    # 3. GET /api/v1/admin/stats
    stats_res = client.get("/api/v1/admin/stats", headers=headers)
    assert stats_res.status_code == 200
    assert stats_res.json()["total_users"] >= 1

    # 4. POST /api/v1/admin/models/retrain
    retrain_res = client.post("/api/v1/admin/models/retrain", headers=headers)
    assert retrain_res.status_code == 201
    assert "metrics" in retrain_res.json()

    # 5. GET /api/v1/scans with search query filter
    scans_res = client.get("/api/v1/scans?q=paypa1&classification=ALL", headers=headers)
    assert scans_res.status_code == 200

def run_all_phase3_tests():
    print("==================================================")
    print("PHISHGUARD AI - PHASE 3 AUTOMATED VERIFICATION")
    print("==================================================")

    setup_module(None)

    print("[1/3] Testing Email RFC 822 Header Parsing & Security Analysis...")
    test_email_security_parsing()
    print("  [OK] Email Security & Header Inspection: SUCCESS")

    print("[2/3] Testing Scikit-Learn Random Forest Pipeline & Inference...")
    test_ml_model_pipeline()
    print("  [OK] ML Model Training, Persistence & Probability Scoring: SUCCESS")

    print("[3/3] Testing Phase 3 API Endpoints (Email, Admin, Retrain, Filter)...")
    test_phase3_api_endpoints()
    print("  [OK] Email Scan, Admin Console & Retraining API: SUCCESS")

    teardown_module(None)

    print("\nALL PHASE 3 VERIFICATION TESTS PASSED SUCCESSFULLY!")

if __name__ == "__main__":
    run_all_phase3_tests()
