"""Valorynn web application."""
from __future__ import annotations

import hashlib
import sqlite3
from collections import Counter
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Annotated

from fastapi import BackgroundTasks, FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app import database
from app.config import settings
from app.reporting import html_report, pdf_report
from app.scanner import execute_scan, validate_target
from app.scoring import projected_score
from app.security import create_session, hash_password, new_csrf_token, read_session, valid_csrf, verify_password

BASE_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))


@asynccontextmanager
async def lifespan(_: FastAPI):
    database.initialize()
    yield


app = FastAPI(title="Valorynn", version="0.1.0", lifespan=lifespan)
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:"
    return response


def current_user(request: Request) -> dict | None:
    user_id = read_session(request.cookies.get("valorynn_session"))
    return database.one("SELECT id,name,email,account_type,institution,course_year FROM users WHERE id=?", (user_id,)) if user_id else None


def require_user(request: Request) -> dict:
    user = current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Sign in is required.")
    return user


def check_csrf(request: Request, submitted: str) -> None:
    if not valid_csrf(submitted, request.cookies.get("valorynn_csrf")):
        raise HTTPException(status_code=403, detail="Your form expired. Refresh the page and try again.")


def render(request: Request, name: str, context: dict | None = None, status_code: int = 200) -> HTMLResponse:
    context = context or {}
    csrf_token = request.cookies.get("valorynn_csrf") or new_csrf_token()
    response = templates.TemplateResponse(request, name, {"user": current_user(request), "csrf_token": csrf_token, **context}, status_code=status_code)
    if not request.cookies.get("valorynn_csrf"):
        response.set_cookie("valorynn_csrf", csrf_token, httponly=True, secure=settings.cookie_secure, samesite="lax", max_age=60 * 60 * 12)
    return response


def redirect(path: str) -> RedirectResponse:
    return RedirectResponse(path, status_code=303)


def owned_application_or_404(app_id: int, user_id: int) -> dict:
    application = database.get_owned_application(app_id, user_id)
    if not application:
        raise HTTPException(status_code=404, detail="Application not found.")
    return application


def owned_scan_or_404(scan_id: int, user_id: int) -> dict:
    scan = database.get_owned_scan(scan_id, user_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found.")
    return scan


@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    user = current_user(request)
    if user:
        return redirect("/dashboard")
    return templates.TemplateResponse(request, "landing.html", {"user": user})


@app.get("/register", response_class=HTMLResponse)
def register_page(request: Request):
    return render(request, "register.html")


@app.post("/register")
def register(
    request: Request,
    csrf_token: Annotated[str, Form()],
    name: Annotated[str, Form()],
    email: Annotated[str, Form()],
    password: Annotated[str, Form()],
    account_type: Annotated[str, Form()],
    institution: Annotated[str | None, Form()] = None,
    course_year: Annotated[str | None, Form()] = None,
):
    check_csrf(request, csrf_token)
    if account_type not in {"student", "developer", "organization"}:
        return render(request, "register.html", {"error": "Choose a valid account type."}, 422)
    if not name.strip() or "@" not in email or len(email) > 254:
        return render(request, "register.html", {"error": "Enter a valid name and email address."}, 422)
    try:
        user_id = database.create_user(name, email, hash_password(password), account_type, institution, course_year)
    except ValueError as error:
        return render(request, "register.html", {"error": str(error)}, 422)
    except sqlite3.IntegrityError:
        return render(request, "register.html", {"error": "An account with that email already exists."}, 409)
    response = redirect("/dashboard")
    response.set_cookie("valorynn_session", create_session(user_id), httponly=True, secure=settings.cookie_secure, samesite="lax", max_age=60 * 60 * 12)
    return response


@app.get("/signin", response_class=HTMLResponse)
def signin_page(request: Request):
    return render(request, "signin.html")


@app.post("/signin")
def signin(request: Request, csrf_token: Annotated[str, Form()], email: Annotated[str, Form()], password: Annotated[str, Form()]):
    check_csrf(request, csrf_token)
    user = database.one("SELECT * FROM users WHERE email=?", (email.strip().lower(),))
    if not user or not verify_password(password, user["password_hash"]):
        return render(request, "signin.html", {"error": "Email or password is incorrect."}, 401)
    response = redirect("/dashboard")
    response.set_cookie("valorynn_session", create_session(user["id"]), httponly=True, secure=settings.cookie_secure, samesite="lax", max_age=60 * 60 * 12)
    return response


@app.post("/signout")
def signout(request: Request, csrf_token: Annotated[str, Form()]):
    check_csrf(request, csrf_token)
    response = redirect("/signin")
    response.delete_cookie("valorynn_session")
    return response


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request, q: str = ""):
    user = require_user(request)
    applications = database.list_applications(user["id"])
    if q.strip():
        needle = q.lower().strip()
        applications = [item for item in applications if needle in item["name"].lower() or needle in item["target_url"].lower()]
    completed = [app for app in applications if app["latest_score"] is not None]
    return render(request, "dashboard.html", {"applications": applications, "query": q, "app_count": len(applications), "scanned_count": len(completed)})


@app.get("/applications/new", response_class=HTMLResponse)
def new_application_page(request: Request):
    require_user(request)
    return render(request, "application_form.html")


@app.post("/applications")
async def create_application(
    request: Request,
    csrf_token: Annotated[str, Form()],
    name: Annotated[str, Form()],
    target_url: Annotated[str, Form()],
    repository_url: Annotated[str | None, Form()] = None,
    source_zip: UploadFile | None = File(default=None),
):
    user = require_user(request)
    check_csrf(request, csrf_token)
    if not name.strip() or len(name.strip()) > 120:
        return render(request, "application_form.html", {"error": "Enter an application name of up to 120 characters."}, 422)
    try:
        target = validate_target(target_url)
    except ValueError as error:
        return render(request, "application_form.html", {"error": str(error)}, 422)
    filename = None
    file_hash = None
    if source_zip and source_zip.filename:
        if not source_zip.filename.lower().endswith(".zip"):
            return render(request, "application_form.html", {"error": "Source review accepts ZIP files only."}, 422)
        content = await source_zip.read(settings.max_source_bytes + 1)
        if len(content) > settings.max_source_bytes:
            return render(request, "application_form.html", {"error": "The source ZIP exceeds the 5 MB review limit."}, 422)
        filename = Path(source_zip.filename).name
        file_hash = hashlib.sha256(content).hexdigest()
        # Uploaded source is intentionally discarded after this metadata check. A new
        # archive may be supplied per scan, avoiding retention of possible secrets.
    app_id = database.create_application(user["id"], name, target.url, repository_url.strip() if repository_url else None, filename, file_hash)
    return redirect(f"/applications/{app_id}")


@app.get("/applications/{app_id}", response_class=HTMLResponse)
def application_detail(request: Request, app_id: int):
    user = require_user(request)
    application = owned_application_or_404(app_id, user["id"])
    scans = database.list_scans(app_id)
    return render(request, "application_detail.html", {"application": application, "scans": scans})


@app.post("/applications/{app_id}/delete")
def delete_application(request: Request, app_id: int, csrf_token: Annotated[str, Form()]):
    user = require_user(request)
    check_csrf(request, csrf_token)
    owned_application_or_404(app_id, user["id"])
    database.delete_owned_application(app_id, user["id"])
    return redirect("/dashboard")


@app.post("/applications/{app_id}/scan")
async def start_scan(
    request: Request,
    background_tasks: BackgroundTasks,
    app_id: int,
    csrf_token: Annotated[str, Form()],
    authorization_confirmation: Annotated[str, Form()],
    source_zip: UploadFile | None = File(default=None),
):
    user = require_user(request)
    check_csrf(request, csrf_token)
    application = owned_application_or_404(app_id, user["id"])
    if authorization_confirmation != "authorized":
        return render(request, "application_detail.html", {"application": application, "scans": database.list_scans(app_id), "error": "You must confirm that you own or are authorized to assess this target."}, 422)
    one_hour_ago = (datetime.now(UTC) - timedelta(hours=1)).isoformat(timespec="seconds")
    if database.recent_scan_count(user["id"], one_hour_ago) >= 5:
        return render(request, "application_detail.html", {"application": application, "scans": database.list_scans(app_id), "error": "Scan limit reached: wait before starting another assessment (maximum 5 per account each hour)."}, 429)
    source_bytes = None
    source_filename = None
    if source_zip and source_zip.filename:
        if not source_zip.filename.lower().endswith(".zip"):
            return render(request, "application_detail.html", {"application": application, "scans": database.list_scans(app_id), "error": "Source review accepts ZIP files only."}, 422)
        source_bytes = await source_zip.read(settings.max_source_bytes + 1)
        if len(source_bytes) > settings.max_source_bytes:
            return render(request, "application_detail.html", {"application": application, "scans": database.list_scans(app_id), "error": "The source ZIP exceeds the 5 MB review limit."}, 422)
        source_filename = Path(source_zip.filename).name
    scan_id = database.create_scan(app_id)
    background_tasks.add_task(execute_scan, scan_id, source_bytes, source_filename)
    return redirect(f"/scans/{scan_id}/progress")


@app.get("/scans/{scan_id}/progress", response_class=HTMLResponse)
def scan_progress(request: Request, scan_id: int):
    user = require_user(request)
    scan = owned_scan_or_404(scan_id, user["id"])
    if scan["status"] == "completed":
        return redirect(f"/scans/{scan_id}")
    return render(request, "scan_progress.html", {"scan": scan})


@app.get("/scans/{scan_id}/status")
def scan_status(request: Request, scan_id: int):
    user = require_user(request)
    scan = owned_scan_or_404(scan_id, user["id"])
    return {"status": scan["status"], "result_url": f"/scans/{scan_id}" if scan["status"] == "completed" else None, "error": scan["error_message"]}


@app.get("/scans/{scan_id}", response_class=HTMLResponse)
def scan_results(request: Request, scan_id: int):
    user = require_user(request)
    scan = owned_scan_or_404(scan_id, user["id"])
    if scan["status"] != "completed":
        return redirect(f"/scans/{scan_id}/progress")
    findings = database.findings_for_scan(scan_id)
    groups = {level: [item for item in findings if item["severity"] == level] for level in ("critical", "high", "medium", "low", "info")}
    return render(request, "scan_results.html", {"scan": scan, "findings": findings, "groups": groups, "counts": Counter(item["severity"] for item in findings)})


@app.post("/scans/{scan_id}/delete")
def delete_scan(request: Request, scan_id: int, csrf_token: Annotated[str, Form()]):
    user = require_user(request)
    check_csrf(request, csrf_token)
    scan = owned_scan_or_404(scan_id, user["id"])
    database.delete_owned_scan(scan_id, user["id"])
    return redirect(f"/applications/{scan['application_id']}")


@app.get("/scans/{scan_id}/simulate")
def simulate(request: Request, scan_id: int, finding_id: list[int] | None = None):
    user = require_user(request)
    scan = owned_scan_or_404(scan_id, user["id"])
    findings = database.findings_for_scan(scan_id)
    selected = [item for item in findings if item["id"] in set(finding_id or [])]
    return {"current_score": scan["score"], "projected_score": projected_score(scan["score"], selected), "selected_count": len(selected), "risk_reduction_points": sum(item["score_impact"] for item in selected), "note": "Projection assumes selected remediations fully resolve their recorded finding. Re-scan to verify."}


@app.get("/scans/{scan_id}/report.html")
def download_html_report(request: Request, scan_id: int):
    user = require_user(request)
    scan = owned_scan_or_404(scan_id, user["id"])
    return Response(html_report(scan, database.findings_for_scan(scan_id)), media_type="text/html", headers={"Content-Disposition": f'attachment; filename="valorynn-scan-{scan_id}.html"'})


@app.get("/scans/{scan_id}/report.pdf")
def download_pdf_report(request: Request, scan_id: int):
    user = require_user(request)
    scan = owned_scan_or_404(scan_id, user["id"])
    return Response(pdf_report(scan, database.findings_for_scan(scan_id)), media_type="application/pdf", headers={"Content-Disposition": f'attachment; filename="valorynn-scan-{scan_id}.pdf"'})


@app.get("/applications/{app_id}/compare", response_class=HTMLResponse)
def compare_scans(request: Request, app_id: int, before: int | None = None, after: int | None = None):
    user = require_user(request)
    application = owned_application_or_404(app_id, user["id"])
    scans = [item for item in database.list_scans(app_id) if item["status"] == "completed"]
    if len(scans) < 2:
        return render(request, "comparison.html", {"application": application, "scans": scans, "error": "Complete at least two scans to compare progress."})
    before_scan = owned_scan_or_404(before, user["id"]) if before else scans[1]
    after_scan = owned_scan_or_404(after, user["id"]) if after else scans[0]
    if before_scan["application_id"] != app_id or after_scan["application_id"] != app_id:
        raise HTTPException(404, "Both scans must belong to this application.")
    before_findings = database.findings_for_scan(before_scan["id"])
    after_findings = database.findings_for_scan(after_scan["id"])
    before_titles = {item["title"] for item in before_findings}
    after_titles = {item["title"] for item in after_findings}
    return render(request, "comparison.html", {"application": application, "scans": scans, "before": before_scan, "after": after_scan, "score_change": after_scan["score"] - before_scan["score"], "resolved": sorted(before_titles - after_titles), "new": sorted(after_titles - before_titles)})
