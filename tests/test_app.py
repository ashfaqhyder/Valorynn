import uuid

import pytest
from fastapi.testclient import TestClient

from app.database import initialize
from app.main import app


@pytest.fixture(autouse=True)
def setup_db():
    initialize()


def test_home_serves_public_landing_page():
    client = TestClient(app)
    response = client.get("/", follow_redirects=False)
    assert response.status_code == 200
    assert 'class="landing-page"' in response.text
    assert "Know what makes your application vulnerable." in response.text
    assert 'href="/signin"' in response.text
    assert 'href="/register"' in response.text
    assert '/static/images/valorynn-logo.png' in response.text
    assert 'class="brand-lockup nav-brand"' in response.text
    assert 'class="brand-symbol brand-symbol--light-mode"' in response.text
    assert 'class="brand-title">VALORYNN</span>' in response.text
    assert 'aria-label="Switch to light mode"' in response.text
    assert 'class="theme-icon-dark"' in response.text
    assert 'style="display: none;"' not in response.text
    assert response.text.index('/static/theme-init.js') < response.text.index('rel="stylesheet"')
    assert response.text.index('class="brand-splash initial-page-loader"') < response.text.index('<nav')
    assert response.text.index('<section class="developer-credit"') > response.text.rindex('</footer>')
    assert '/static/images/ashfaq-hyder-logo.png' in response.text
    assert 'href="https://ashfaqhydercs.vercel.app/"' in response.text
    assert 'aria-label="Visit ASHFAQ HYDER C S\'s website (opens in a new tab)"' in response.text


def test_supplied_brand_assets_are_served_as_static_files():
    client = TestClient(app)

    logo = client.get("/static/images/valorynn-logo.png")
    light_logo = client.get("/static/images/valorynn-logo-light.png")
    wordmark = client.get("/static/images/valorynn-wordmark.png")
    developer_logo = client.get("/static/images/ashfaq-hyder-logo.png")
    font = client.get("/static/anurati-regular.otf")
    stylesheet = client.get("/static/styles.css")
    theme_script = client.get("/static/theme-init.js")

    assert logo.status_code == 200
    assert logo.headers["content-type"].startswith("image/png")
    assert logo.content.startswith(b"\x89PNG\r\n\x1a\n")
    assert light_logo.status_code == 200
    assert light_logo.content.startswith(b"\x89PNG\r\n\x1a\n")
    assert wordmark.status_code == 200
    assert wordmark.headers["content-type"].startswith("image/png")
    assert wordmark.content.startswith(b"\x89PNG\r\n\x1a\n")
    assert developer_logo.status_code == 200
    assert developer_logo.headers["content-type"].startswith("image/png")
    assert developer_logo.content.startswith(b"\x89PNG\r\n\x1a\n")
    assert font.status_code == 200
    assert font.content[:4] == b"OTTO"
    assert stylesheet.status_code == 200
    assert '@font-face' in stylesheet.text
    assert 'url("/static/anurati-regular.otf")' in stylesheet.text
    assert '--theme-toggle-bg:' in stylesheet.text
    assert '--navbar-bg:' in stylesheet.text
    assert ':root[data-theme="light"]' in stylesheet.text
    assert '[data-theme="light"] .theme-icon-dark { display: block; }' in stylesheet.text
    assert theme_script.status_code == 200
    assert "localStorage.getItem('valorynn-theme')" in theme_script.text


def test_register_and_signin_flow():
    client = TestClient(app)
    unique_email = f"user_{uuid.uuid4().hex[:8]}@valorynn-test.org"

    signin_page = TestClient(app).get("/signin")
    assert signin_page.status_code == 200
    assert '/static/images/valorynn-logo.png' in signin_page.text
    assert 'class="brand-lockup auth-brand"' in signin_page.text
    assert 'aria-label="Switch to light mode"' in signin_page.text
    
    # 1. Get register page to obtain CSRF cookie
    get_res = client.get("/register")
    assert get_res.status_code == 200
    assert '/static/images/valorynn-logo.png' in get_res.text
    assert 'class="brand-lockup auth-brand"' in get_res.text
    assert 'aria-label="Switch to light mode"' in get_res.text
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
    assert '/static/images/valorynn-logo.png' in dash_res.text
    assert 'class="brand-lockup nav-brand"' in dash_res.text
    assert 'aria-label="Switch to light mode"' in dash_res.text
