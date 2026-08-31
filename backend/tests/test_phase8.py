import os
import sys
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.main import app
from app.database.session import Base, get_db
from app.services.security_auditor import perform_security_audit
from app.services.benchmark_engine import run_system_performance_benchmark
from app.core.rate_limiter import _request_history

SQLALCHEMY_DATABASE_URL = "sqlite:///./test_phishguard_phase8.db"
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
    if os.path.exists("test_phishguard_phase8.db"):
        os.remove("test_phishguard_phase8.db")

def test_security_auditor_standalone():
    audit_res = perform_security_audit()
    assert audit_res["overall_score"] >= 80
    assert audit_res["status"] in ["COMPLIANT", "DEGRADED"]
    assert audit_res["total_checks"] >= 5
    assert len(audit_res["recommendations"]) >= 1

def test_performance_benchmark_standalone():
    bench_res = run_system_performance_benchmark(iterations=5)
    assert bench_res["iterations"] == 5
    assert bench_res["average_latency_ms"] >= 0
    assert bench_res["throughput_scans_per_sec"] > 0
    assert bench_res["performance_rating"] in ["EXCELLENT", "GOOD"]

def test_phase8_admin_endpoints():
    client = TestClient(app)
    _request_history.clear()

    # 1. Register Superuser / Admin
    reg = client.post("/api/v1/auth/register", json={"email": "admin_phase8@phishguard.sec", "password": "AdminPassPhase8!"})
    assert reg.status_code == 201

    login = client.post("/api/v1/auth/login", data={"username": "admin_phase8@phishguard.sec", "password": "AdminPassPhase8!"})
    token = login.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # 2. Test GET /api/v1/admin/security-audit
    audit_res = client.get("/api/v1/admin/security-audit", headers=headers)
    assert audit_res.status_code == 200
    audit_data = audit_res.json()
    assert audit_data["overall_score"] >= 80

    # 3. Test POST /api/v1/admin/benchmark
    bench_res = client.post("/api/v1/admin/benchmark?iterations=5", headers=headers)
    assert bench_res.status_code == 200
    bench_data = bench_res.json()
    assert bench_data["iterations"] == 5

def run_all_phase8_tests():
    print("==================================================")
    print("PHISHGUARD AI - PHASE 8 AUTOMATED VERIFICATION")
    print("==================================================")

    setup_module(None)

    print("[1/3] Testing Automated Security Compliance Auditor...")
    test_security_auditor_standalone()
    print("  [OK] OWASP & System Security Compliance Engine: SUCCESS")

    print("[2/3] Testing Sub-second Performance & Latency Benchmark Engine...")
    test_performance_benchmark_standalone()
    print("  [OK] System Performance & Throughput Benchmarking: SUCCESS")

    print("[3/3] Testing Phase 8 Admin Console Security Endpoints...")
    test_phase8_admin_endpoints()
    print("  [OK] Security Audit & Performance Endpoints: SUCCESS")

    teardown_module(None)

    print("\nALL PHASE 8 VERIFICATION TESTS PASSED SUCCESSFULLY!")

if __name__ == "__main__":
    run_all_phase8_tests()
