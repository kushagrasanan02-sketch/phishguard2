import os
import sys
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.main import app
from app.database.session import Base, get_db
from app.services.threat_feed import check_domain_whitelist
from app.services.risk_engine import calculate_risk_score
from app.core.rate_limiter import _request_history

SQLALCHEMY_DATABASE_URL = "sqlite:///./test_phishguard_phase5.db"
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
    if os.path.exists("test_phishguard_phase5.db"):
        os.remove("test_phishguard_phase5.db")

def test_domain_whitelist_threat_feed():
    # Legitimate official domain test
    is_whitelisted, brand = check_domain_whitelist("paypal.com")
    assert is_whitelisted is True
    assert "PayPal" in brand

    score, classification, prob, factors, positive, rec = calculate_risk_score({"domain": "paypal.com"})
    assert score == 0
    assert classification == "SAFE"
    assert "Verified Official Domain" in positive[0]

    # Phishing domain test
    is_phish_white, phish_brand = check_domain_whitelist("paypa1-verify.xyz")
    assert is_phish_white is False

def test_api_key_authentication():
    client = TestClient(app)
    _request_history.clear()

    # 1. Register User
    reg = client.post("/api/v1/auth/register", json={"email": "apikey_user@phishguard.sec", "password": "UserPass123!"})
    assert reg.status_code == 201

    login = client.post("/api/v1/auth/login", data={"username": "apikey_user@phishguard.sec", "password": "UserPass123!"})
    token = login.json()["access_token"]
    jwt_headers = {"Authorization": f"Bearer {token}"}

    # 2. Generate API Key
    key_res = client.post("/api/v1/auth/api-keys", json={"name": "CLI Integration Key"}, headers=jwt_headers)
    assert key_res.status_code == 201
    key_data = key_res.json()
    assert "api_key" in key_data
    api_key_str = key_data["api_key"]
    assert api_key_str.startswith("pg_live_")

    # 3. List API Keys
    list_res = client.get("/api/v1/auth/api-keys", headers=jwt_headers)
    assert list_res.status_code == 200
    assert len(list_res.json()) >= 1

    # 4. Invoke Scan API passing X-API-Key HTTP header (without Bearer token)
    apikey_headers = {"X-API-Key": api_key_str}
    scan_res = client.post("/api/v1/scans/url", json={"url": "https://paypal.com"}, headers=apikey_headers)
    assert scan_res.status_code == 201
    assert scan_res.json()["classification"] == "SAFE"

    # 5. Revoke API Key
    key_id = key_data["id"]
    del_res = client.delete(f"/api/v1/auth/api-keys/{key_id}", headers=jwt_headers)
    assert del_res.status_code == 204

def test_ci_cd_workflow_exists():
    ci_file_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".github", "workflows", "ci.yml"))
    assert os.path.exists(ci_file_path) is True

def run_all_phase5_tests():
    print("==================================================")
    print("PHISHGUARD AI - PHASE 5 AUTOMATED VERIFICATION")
    print("==================================================")

    setup_module(None)

    print("[1/3] Testing Domain Whitelist Engine & False Positive Prevention...")
    test_domain_whitelist_threat_feed()
    print("  [OK] Whitelist Engine & Threat Feed Verification: SUCCESS")

    print("[2/3] Testing API Key Generation, Authentication (X-API-Key) & Revocation...")
    test_api_key_authentication()
    print("  [OK] Programmatic API Key Management: SUCCESS")

    print("[3/3] Testing GitHub Actions CI/CD Workflow Setup...")
    test_ci_cd_workflow_exists()
    print("  [OK] CI/CD Workflow Configuration: SUCCESS")

    teardown_module(None)

    print("\nALL PHASE 5 VERIFICATION TESTS PASSED SUCCESSFULLY!")

if __name__ == "__main__":
    run_all_phase5_tests()
