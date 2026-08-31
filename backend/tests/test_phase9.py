import os
import sys
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.main import app
from app.database.session import Base, get_db
from app.services.chat_assistant import analyze_threat_query_with_guard_ai
from app.core.rate_limiter import _request_history

SQLALCHEMY_DATABASE_URL = "sqlite:///./test_phishguard_phase9.db"
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
    if os.path.exists("test_phishguard_phase9.db"):
        os.remove("test_phishguard_phase9.db")

def test_guard_ai_chat_assistant_logic():
    # 1. Phishing query test
    res = analyze_threat_query_with_guard_ai("How do I mitigate phishing targeting paypal?")
    assert "GuardAI Assessment" in res["response"]
    assert len(res["mitigation_playbook"]) >= 1

    # 2. SSRF mitigation query test
    ssrf_res = analyze_threat_query_with_guard_ai("What is PhishGuard's SSRF policy?")
    assert "RFC 1918" in ssrf_res["response"]
    assert len(ssrf_res["mitigation_playbook"]) >= 1

def test_phase9_chat_and_map_endpoints():
    client = TestClient(app)
    _request_history.clear()

    # 1. POST /api/v1/chat/analyze
    chat_payload = {
        "query": "Explain email SPF and DKIM failures",
        "scan_context": {"domain": "suspicious-bank.xyz", "risk_score": 85}
    }
    chat_res = client.post("/api/v1/chat/analyze", json=chat_payload)
    assert chat_res.status_code == 200
    c_data = chat_res.json()
    assert "mitigation_playbook" in c_data
    assert c_data["model_version"] == "GuardAI-SOC-v2.5"

    # 2. GET /api/v1/threats/map
    map_res = client.get("/api/v1/threats/map")
    assert map_res.status_code == 200
    m_data = map_res.json()
    assert "threat_origins" in m_data
    assert len(m_data["threat_origins"]) >= 1
    assert "top_impersonated_brands" in m_data

def run_all_phase9_tests():
    print("==================================================")
    print("PHISHGUARD AI - PHASE 9 AUTOMATED VERIFICATION")
    print("==================================================")

    setup_module(None)

    print("[1/2] Testing GuardAI SOC Security Analyst Reasoning Engine...")
    test_guard_ai_chat_assistant_logic()
    print("  [OK] GuardAI Assistant Threat Analysis & Playbooks: SUCCESS")

    print("[2/2] Testing GuardAI Chat API & Global Threat Map Endpoints...")
    test_phase9_chat_and_map_endpoints()
    print("  [OK] GuardAI Chat API & Global Threat Map Intelligence: SUCCESS")

    teardown_module(None)

    print("\nALL PHASE 9 VERIFICATION TESTS PASSED SUCCESSFULLY!")

if __name__ == "__main__":
    run_all_phase9_tests()
