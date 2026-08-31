import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.main import app
from app.database.session import Base, get_db
from app.core.security import get_password_hash, verify_password

# Use in-memory SQLite database for fast automated testing
SQLALCHEMY_DATABASE_URL = "sqlite:///./test_phishguard.db"

engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def override_get_db():
    try:
        db = TestingSessionLocal()
        yield db
    finally:
        db.close()

app.dependency_overrides[get_db] = override_get_db

@pytest.fixture(autouse=True)
def setup_database():
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)

client = TestClient(app)

def test_password_hashing():
    password = "SuperSecretPassword2026!"
    hashed = get_password_hash(password)
    assert verify_password(password, hashed) is True
    assert verify_password("WrongPassword", hashed) is False

def test_health_check_endpoint():
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] in ["healthy", "degraded"]
    assert "version" in data

def test_user_registration_and_login():
    # 1. Register first user (should automatically become ADMIN)
    register_payload = {
        "email": "admin@phishguard.sec",
        "password": "AdminPassword123!",
        "full_name": "Lead Security Analyst"
    }
    reg_response = client.post("/api/v1/auth/register", json=register_payload)
    assert reg_response.status_code == 201
    reg_data = reg_response.json()
    assert reg_data["email"] == "admin@phishguard.sec"
    assert reg_data["role"] == "ADMIN"

    # 2. Login with valid credentials
    login_payload = {
        "username": "admin@phishguard.sec",
        "password": "AdminPassword123!"
    }
    login_response = client.post("/api/v1/auth/login", data=login_payload)
    assert login_response.status_code == 200
    token_data = login_response.json()
    assert "access_token" in token_data
    assert token_data["token_type"] == "bearer"

    # 3. Access protected /me endpoint with access token
    headers = {"Authorization": f"Bearer {token_data['access_token']}"}
    me_response = client.get("/api/v1/auth/me", headers=headers)
    assert me_response.status_code == 200
    me_data = me_response.json()
    assert me_data["email"] == "admin@phishguard.sec"
    assert me_data["role"] == "ADMIN"
