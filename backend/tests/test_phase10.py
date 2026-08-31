import os
import sys
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.main import app
from app.database.session import Base, get_db
from app.services.release_certifier import certifier_system_release_candidate
from app.core.rate_limiter import _request_history
from app.core.security import create_access_token
from app.models.user import User

SQLALCHEMY_DATABASE_URL = "sqlite:///./test_phishguard_phase10.db"
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
    if os.path.exists("test_phishguard_phase10.db"):
        os.remove("test_phishguard_phase10.db")

def test_release_candidate_certification_service():
    db = TestingSessionLocal()
    cert = certifier_system_release_candidate(db)
    db.close()

    assert cert["release_version"] == "v1.0.0-RC1"
    assert cert["certified"] == True
    assert cert["certification_status"] == "ENTERPRISE_GOLD_CERTIFIED"
    assert cert["passed_checks_count"] >= 5

def test_phase10_certification_endpoint():
    client = TestClient(app)
    _request_history.clear()

    db = TestingSessionLocal()
    admin_user = User(
        email="admin_p10@phishguard.ai",
        hashed_password="secret_hashed_pw",
        role="ADMIN",
        is_active=True
    )
    db.add(admin_user)
    db.commit()
    db.refresh(admin_user)
    db.close()

    token = create_access_token(admin_user.id)
    headers = {"Authorization": f"Bearer {token}"}

    res = client.get("/api/v1/admin/certification", headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert data["certified"] == True
    assert data["certification_status"] == "ENTERPRISE_GOLD_CERTIFIED"
    assert "certification_checks" in data

def run_all_phase10_tests():
    print("==================================================")
    print("PHISHGUARD AI - PHASE 10 AUTOMATED VERIFICATION")
    print("==================================================")

    setup_module(None)

    print("[1/2] Testing Release Candidate v1.0 Certification Engine...")
    test_release_candidate_certification_service()
    print("  [OK] Release Candidate Certification Engine: SUCCESS")

    print("[2/2] Testing Admin Release Certification API Endpoint...")
    test_phase10_certification_endpoint()
    print("  [OK] Admin Certification API Endpoint: SUCCESS")

    teardown_module(None)

    print("\nALL PHASE 10 VERIFICATION TESTS PASSED SUCCESSFULLY!")

if __name__ == "__main__":
    run_all_phase10_tests()
