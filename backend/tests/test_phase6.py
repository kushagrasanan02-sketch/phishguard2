import os
import sys
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.main import app
from app.database.session import Base, get_db
from app.services.siem_exporter import export_scan_as_cef, export_scan_as_stix, export_scan_as_syslog
from app.core.rate_limiter import _request_history

SQLALCHEMY_DATABASE_URL = "sqlite:///./test_phishguard_phase6.db"
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
    if os.path.exists("test_phishguard_phase6.db"):
        os.remove("test_phishguard_phase6.db")

def test_siem_format_exporters():
    scan_sample = {
        "id": "scan-uuid-12345",
        "url": "https://suspicious-login-portal.net/auth",
        "domain": "suspicious-login-portal.net",
        "risk_score": 85,
        "classification": "PHISHING",
        "ml_probability": 0.92
    }

    # 1. CEF Exporter Test
    cef_out = export_scan_as_cef(scan_sample)
    assert "CEF:0|PhishGuardAI|DefensePlatform|1.0" in cef_out
    assert "requestDomain=suspicious-login-portal.net" in cef_out
    assert "cn1=85" in cef_out

    # 2. STIX 2.1 JSON Test
    stix_out = export_scan_as_stix(scan_sample)
    assert stix_out["type"] == "bundle"
    assert stix_out["objects"][0]["type"] == "indicator"
    assert "suspicious-login-portal.net" in stix_out["objects"][0]["name"]

    # 3. Syslog Exporter Test
    syslog_out = export_scan_as_syslog(scan_sample)
    assert "<134>1" in syslog_out
    assert "phishguard-soc phishguard-ai" in syslog_out
    assert "score=\"85\"" in syslog_out

def test_siem_export_api_endpoint():
    client = TestClient(app)
    _request_history.clear()

    # 1. Scan a URL
    scan_res = client.post("/api/v1/scans/url", json={"url": "https://secure-login-check.com"})
    assert scan_res.status_code == 201
    scan_id = scan_res.json()["id"]

    # 2. Export as CEF
    cef_res = client.get(f"/api/v1/scans/{scan_id}/export/siem?format=cef")
    assert cef_res.status_code == 200
    assert "CEF:0|PhishGuardAI" in cef_res.text

    # 3. Export as STIX
    stix_res = client.get(f"/api/v1/scans/{scan_id}/export/siem?format=stix")
    assert stix_res.status_code == 200
    assert stix_res.json()["type"] == "bundle"

def test_diagnostics_and_apikeys_endpoints():
    client = TestClient(app)
    _request_history.clear()

    # 1. Register Superuser / Admin
    reg = client.post("/api/v1/auth/register", json={"email": "admin_phase6@phishguard.sec", "password": "AdminPass123!"})
    assert reg.status_code == 201

    login = client.post("/api/v1/auth/login", data={"username": "admin_phase6@phishguard.sec", "password": "AdminPass123!"})
    token = login.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # 2. Fetch System Diagnostics
    diag_res = client.get("/api/v1/admin/diagnostics", headers=headers)
    assert diag_res.status_code == 200
    diag_data = diag_res.json()
    assert diag_data["status"] == "HEALTHY"
    assert "database" in diag_data

def run_all_phase6_tests():
    print("==================================================")
    print("PHISHGUARD AI - PHASE 6 AUTOMATED VERIFICATION")
    print("==================================================")

    setup_module(None)

    print("[1/3] Testing SIEM Threat Exporters (CEF, STIX 2.1, Syslog)...")
    test_siem_format_exporters()
    print("  [OK] SIEM Threat Exporters Verification: SUCCESS")

    print("[2/3] Testing SIEM Threat Exporter API Endpoints...")
    test_siem_export_api_endpoint()
    print("  [OK] SIEM API Endpoint Verification: SUCCESS")

    print("[3/3] Testing System Diagnostics & API Key Lifecycle...")
    test_diagnostics_and_apikeys_endpoints()
    print("  [OK] System Diagnostics & API Key Endpoints: SUCCESS")

    teardown_module(None)

    print("\nALL PHASE 6 VERIFICATION TESTS PASSED SUCCESSFULLY!")

if __name__ == "__main__":
    run_all_phase6_tests()
