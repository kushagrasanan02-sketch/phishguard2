import os
import sys
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.main import app
from app.database.session import Base, get_db
from app.services.soar_engine import dispatch_soar_mitigation_playbook
from app.core.rate_limiter import _request_history
from app.core.security import create_access_token
from app.models.user import User
from app.models.scan import Scan

SQLALCHEMY_DATABASE_URL = "sqlite:///./test_phishguard_phase11.db"
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
    if os.path.exists("test_phishguard_phase11.db"):
        os.remove("test_phishguard_phase11.db")

def test_soar_playbook_engine():
    db = TestingSessionLocal()
    scan = Scan(url="http://fake-login-bank.xyz", normalized_url="http://fake-login-bank.xyz", domain="fake-login-bank.xyz", risk_score=88, classification="PHISHING", ml_probability=0.88)
    db.add(scan)
    db.commit()
    db.refresh(scan)

    res = dispatch_soar_mitigation_playbook(scan.id, "firewall_sinkhole", db)
    db.close()

    assert res["status"] == "SUCCESS"
    assert res["target_domain"] == "fake-login-bank.xyz"
    assert len(res["remediation_actions"]) >= 2

def test_phase11_endpoints():
    client = TestClient(app)
    _request_history.clear()

    db = TestingSessionLocal()
    admin_user = User(
        email="admin_p11@phishguard.ai",
        hashed_password="secret_hashed_pw",
        role="ADMIN",
        is_active=True
    )
    db.add(admin_user)
    db.commit()

    scan = Scan(url="http://threat-campaign.xyz", normalized_url="http://threat-campaign.xyz", domain="threat-campaign.xyz", risk_score=95, classification="PHISHING", ml_probability=0.95)
    db.add(scan)
    db.commit()
    db.refresh(scan)

    token = create_access_token(admin_user.id)
    headers = {"Authorization": f"Bearer {token}"}
    db.close()

    # 1. POST /api/v1/soar/dispatch
    soar_payload = {"scan_id": scan.id, "action": "dns_blocklist"}
    s_res = client.post("/api/v1/soar/dispatch", json=soar_payload, headers=headers)
    assert s_res.status_code == 200
    s_data = s_res.json()
    assert s_data["status"] == "SUCCESS"

    # 2. GET /api/v1/threats/graph
    g_res = client.get("/api/v1/threats/graph")
    assert g_res.status_code == 200
    g_data = g_res.json()
    assert "nodes" in g_data
    assert "edges" in g_data
    assert len(g_data["nodes"]) >= 3

def run_all_phase11_tests():
    print("==================================================")
    print("PHISHGUARD AI - PHASE 11 AUTOMATED VERIFICATION")
    print("==================================================")

    setup_module(None)

    print("[1/2] Testing SOAR Incident Response Playbook Engine...")
    test_soar_playbook_engine()
    print("  [OK] SOAR Incident Mitigation Playbooks: SUCCESS")

    print("[2/2] Testing SOAR Dispatch & Threat Relationship Graph Endpoints...")
    test_phase11_endpoints()
    print("  [OK] SOAR API Dispatch & Threat Network Graph: SUCCESS")

    teardown_module(None)

    print("\nALL PHASE 11 VERIFICATION TESTS PASSED SUCCESSFULLY!")

if __name__ == "__main__":
    run_all_phase11_tests()
