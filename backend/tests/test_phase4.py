import os
import sys
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.main import app
from app.database.session import Base, get_db
from app.core.rate_limiter import _request_history

SQLALCHEMY_DATABASE_URL = "sqlite:///./test_phishguard_phase4.db"
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
    Base.metadata.drop_all(bind=engine)
    engine.dispose()
    if os.path.exists("test_phishguard_phase4.db"):
        os.remove("test_phishguard_phase4.db")

def test_rate_limiting_enforcement():
    client = TestClient(app)
    payload = {"url": "https://example.com"}

    # Execute 32 scan requests to trigger rate limit (threshold = 30 / min)
    limit_reached = False
    for i in range(35):
        res = client.post("/api/v1/scans/url", json=payload)
        if res.status_code == 429:
            limit_reached = True
            assert "Rate limit exceeded" in res.json()["detail"]
            assert "Retry-After" in res.headers
            break

    assert limit_reached is True

def test_websocket_and_security_headers():
    client = TestClient(app)

    # 1. Verify Security Headers Middleware
    response = client.get("/")
    assert response.status_code == 200
    assert response.headers.get("X-Frame-Options") == "DENY"
    assert response.headers.get("X-Content-Type-Options") == "nosniff"
    assert "Strict-Transport-Security" in response.headers

    # 2. Test WebSocket connection
    with client.websocket_connect("/api/v1/ws/alerts") as websocket:
        data = websocket.receive_json()
        assert data["event"] == "CONNECTED"

        websocket.send_text("ping")
        resp = websocket.receive_text()
        assert resp == "pong"

def run_all_phase4_tests():
    print("==================================================")
    print("PHISHGUARD AI - PHASE 4 AUTOMATED VERIFICATION")
    print("==================================================")

    setup_module(None)

    print("[1/2] Testing Sliding Window Rate Limiting Enforcement (HTTP 429)...")
    test_rate_limiting_enforcement()
    print("  [OK] Rate Limiter & Abuse Prevention: SUCCESS")

    print("[2/2] Testing WebSockets Telemetry & Security Headers...")
    test_websocket_and_security_headers()
    print("  [OK] WebSockets & Security Headers Compliance: SUCCESS")

    teardown_module(None)

    print("\nALL PHASE 4 VERIFICATION TESTS PASSED SUCCESSFULLY!")

if __name__ == "__main__":
    run_all_phase4_tests()
