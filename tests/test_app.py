import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.database import initialize


import uuid

@pytest.fixture(autouse=True)
def setup_db():
    initialize()


def test_home_redirects_to_signin():
    client = TestClient(app)
    response = client.get("/", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/signin"


def test_register_and_signin_flow():
    client = TestClient(app)
    unique_email = f"user_{uuid.uuid4().hex[:8]}@valorynn-test.org"
    
    # 1. Get register page to obtain CSRF cookie
    get_res = client.get("/register")
    assert get_res.status_code == 200
    csrf_token = get_res.cookies.get("valorynn_csrf")
    assert csrf_token is not None

    # 2. Post registration form
    reg_data = {
        "csrf_token": csrf_token,
        "name": "Test Security Lead",
        "email": unique_email,
        "password": "super-strong-security-pass",
        "account_type": "developer"
    }

    post_res = client.post("/register", data=reg_data, follow_redirects=False)
    assert post_res.status_code == 303
    assert post_res.headers["location"] == "/dashboard"

    # 3. Access dashboard as authenticated user
    dash_res = client.get("/dashboard")
    assert dash_res.status_code == 200
    assert "Test Security Lead" in dash_res.text
