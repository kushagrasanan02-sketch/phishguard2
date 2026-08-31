import os
import sys
import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.main import app
from app.database.session import Base, get_db
from app.security.ssrf import normalize_and_validate_url, validate_ssrf_protection
from app.services.url_extractor import extract_url_features
from app.services.risk_engine import calculate_risk_score

SQLALCHEMY_DATABASE_URL = "sqlite:///./test_phishguard_phase2.db"
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
    if os.path.exists("test_phishguard_phase2.db"):
        os.remove("test_phishguard_phase2.db")

def test_ssrf_protection_rules():
    # 1. Private IPv4 address target should be blocked
    with pytest.raises(HTTPException) as exc_info:
        normalize_and_validate_url("http://127.0.0.1/admin")
    assert "Security Policy Violation" in str(exc_info.value.detail)

    with pytest.raises(HTTPException) as exc_info:
        normalize_and_validate_url("http://169.254.169.254/latest/meta-data")
    assert "Security Policy Violation" in str(exc_info.value.detail)

    # 2. Unsupported protocol should be blocked
    with pytest.raises(HTTPException) as exc_info:
        normalize_and_validate_url("javascript:alert(1)")
    assert "Unsupported protocol" in str(exc_info.value.detail)

    # 3. Valid public URL should pass
    norm_url, scheme, hostname = normalize_and_validate_url("https://account.microsoft.com/services")
    assert norm_url == "https://account.microsoft.com/services"
    assert scheme == "https"
    assert hostname == "account.microsoft.com"

def test_url_feature_extraction():
    # Phishing indicator URL targeting PayPal typo-squatting
    phish_url = "http://paypa1-security-verification.xyz/login?ref=urgent"
    norm_url, scheme, hostname = normalize_and_validate_url(phish_url)
    features = extract_url_features(norm_url, scheme, hostname)

    assert features["https_enabled"] is False
    assert features["unusual_tld"] is True # .xyz
    assert features["has_suspicious_keywords"] is True
    assert "login" in features["detected_keywords"]
    assert features["brand_impersonated"] == "Paypal"

def test_risk_scoring_engine():
    # Clean URL test
    clean_features = {
        "url_length": 35,
        "hostname_length": 15,
        "subdomain_count": 1,
        "has_ip": False,
        "has_at_symbol": False,
        "has_punycode": False,
        "detected_keywords": [],
        "unusual_tld": False,
        "https_enabled": True,
        "brand_impersonated": None
    }
    score, classification, ml_prob, factors, positive_signals, rec = calculate_risk_score(clean_features)
    assert score == 0
    assert classification == "SAFE"
    assert len(factors) == 0

    # High Risk Phishing Target test
    phish_features = {
        "url_length": 90,
        "hostname_length": 35,
        "subdomain_count": 3,
        "has_ip": False,
        "has_at_symbol": True,
        "has_punycode": True,
        "detected_keywords": ["login", "verify", "password"],
        "unusual_tld": True,
        "https_enabled": False,
        "brand_impersonated": "Paypal"
    }
    score, classification, ml_prob, factors, positive_signals, rec = calculate_risk_score(phish_features)
    assert score >= 70
    assert classification in ["HIGH", "CRITICAL", "PHISHING", "SUSPICIOUS"]
    assert len(factors) > 3

def test_scan_api_endpoints():
    client = TestClient(app)

    # 1. POST /api/v1/scans/url (Execute Live Scan Probe)
    payload = {"url": "http://paypa1-login-verify.xyz/auth?user=test"}
    res = client.post("/api/v1/scans/url", json=payload)
    assert res.status_code == 201
    scan_data = res.json()
    assert "id" in scan_data
    assert scan_data["domain"] == "paypa1-login-verify.xyz"
    assert scan_data["risk_score"] > 35
    assert len(scan_data["risk_factors"]) > 0

    scan_id = scan_data["id"]

    # 2. GET /api/v1/scans/{id} (Fetch Report)
    get_res = client.get(f"/api/v1/scans/{scan_id}")
    assert get_res.status_code == 200
    assert get_res.json()["id"] == scan_id

    # 3. GET /api/v1/scans (List History)
    history_res = client.get("/api/v1/scans")
    assert history_res.status_code == 200
    assert len(history_res.json()) >= 1

    # 4. GET /api/v1/scans/dashboard/stats (SOC Metrics)
    stats_res = client.get("/api/v1/scans/dashboard/stats")
    assert stats_res.status_code == 200
    stats = stats_res.json()
    assert stats["total_scans"] >= 1
    assert "threat_distribution" in stats

def run_all_tests():
    print("==================================================")
    print("PHISHGUARD AI - PHASE 2 AUTOMATED VERIFICATION")
    print("==================================================")
    
    setup_module(None)
    
    print("[1/4] Testing SSRF Defense & URL Normalization Rules...")
    test_ssrf_protection_rules()
    print("  [OK] SSRF Protection & Policy Rules: SUCCESS")

    print("[2/4] Testing Lexical & Structural Feature Extraction...")
    test_url_feature_extraction()
    print("  [OK] Feature Extraction Engine: SUCCESS")

    print("[3/4] Testing Transparent Weighted Risk Engine...")
    test_risk_scoring_engine()
    print("  [OK] Risk Scoring & Severity Categorization: SUCCESS")

    print("[4/4] Testing Scan API Endpoints & Database Persistence...")
    test_scan_api_endpoints()
    print("  [OK] Scan API, Report Retrieval & Dashboard Stats: SUCCESS")

    teardown_module(None)

    print("\nALL PHASE 2 VERIFICATION TESTS PASSED SUCCESSFULLY!")

if __name__ == "__main__":
    run_all_tests()
