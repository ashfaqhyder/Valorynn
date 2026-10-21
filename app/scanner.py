"""Low-impact, authorized-target security checks.

This is intentionally a safe assessment layer, not a penetration-testing engine: it
permits only public HTTP(S) hosts, makes a single bounded GET, does not crawl, does
not follow redirects, and rejects private/reserved networks before connecting.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import socket
import ssl
import zipfile
from dataclasses import dataclass
from io import BytesIO
from urllib.parse import urlparse

import httpcore
import httpx

from app.config import settings
from app.database import get_owned_scan, insert_findings, update_scan, utcnow
from app.scoring import SEVERITY_POINTS, calculate_score

SECRET_PATTERNS = [
    (re.compile(r"(?:api[_-]?key|secret|password|token)\s*[:=]\s*['\"][^'\"]{12,}['\"]", re.I), "Potential hard-coded secret"),
    (re.compile(r"AIza[0-9A-Za-z_-]{35}"), "Potential Firebase API key"),
    (re.compile(r"(?:service_role|SUPABASE_SERVICE_ROLE_KEY)\s*[:=]\s*['\"][^'\"]+", re.I), "Potential Supabase service-role secret"),
]
DEBUG_PATTERN = re.compile(r"(?:DEBUG\s*=\s*True|NODE_ENV\s*=\s*['\"]development|FLASK_ENV\s*=\s*['\"]development)", re.I)
CORS_PATTERN = re.compile(r"Access-Control-Allow-Origin\s*[:=]\s*['\"]?\*", re.I)
UPLOAD_PATTERN = re.compile(r"(?:upload|multer|file)\b", re.I)
IPV6_TRANSLATION_PREFIXES = (
    ipaddress.ip_network("64:ff9b::/96"),
    ipaddress.ip_network("64:ff9b:1::/48"),
)


@dataclass
class Target:
    url: str
    hostname: str
    port: int
    addresses: tuple[str, ...]


class _PinnedNetworkBackend(httpcore.SyncBackend):
    """Connect to validated IPs while httpcore retains the original URL hostname for TLS."""

    def __init__(self, hostname: str, port: int, addresses: tuple[str, ...]) -> None:
        super().__init__()
        self._hostname = hostname.rstrip(".").lower()
        self._port = port
        self._addresses = addresses

    def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: list[tuple[int, int, int]] | None = None,
    ) -> httpcore.NetworkStream:
        if host.rstrip(".").lower() != self._hostname or port != self._port:
            raise httpcore.ConnectError("The requested connection does not match the validated target.")
        return super().connect_tcp(
            self._addresses[0],
            port,
            timeout=timeout,
            local_address=local_address,
            socket_options=socket_options,
        )


class _PinnedHTTPTransport(httpx.HTTPTransport):
    def __init__(self, target: Target) -> None:
        super().__init__(trust_env=False)
        # HTTPX does not expose its httpcore network backend in its public transport API.
        # Keep HTTPX's normal request/TLS handling and replace only the TCP connector.
        self._pool._network_backend = _PinnedNetworkBackend(
            target.hostname, target.port, target.addresses
        )


def _finding(category: str, title: str, severity: str, evidence: str, explanation: str, remediation: str, effort: str, source: str = "url-check", confidence: float | None = None) -> dict:
    return {
        "category": category,
        "title": title,
        "severity": severity,
        "evidence": evidence[:1000],
        "explanation": explanation,
        "remediation": remediation,
        "effort": effort,
        "score_impact": SEVERITY_POINTS[severity],
        "confidence": confidence,
        "source": source,
    }


def validate_target(value: str) -> Target:
    parsed = urlparse(value.strip())
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("Enter a complete public http:// or https:// URL without embedded credentials.")
    hostname = parsed.hostname.rstrip(".").lower()
    if hostname in {"localhost", "localhost.localdomain"} or hostname.endswith(".local"):
        raise ValueError("Local and private targets are not permitted.")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    try:
        resolved = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
    except socket.gaierror as error:
        raise ValueError("The target hostname could not be resolved.") from error
    addresses = tuple(dict.fromkeys(info[4][0] for info in resolved))
    if not addresses:
        raise ValueError("The target hostname did not resolve to an address.")
    for address in addresses:
        try:
            ip = ipaddress.ip_address(address)
        except ValueError as error:
            raise ValueError("The target resolved to an invalid IP address.") from error
        if (
            not ip.is_global
            or ip.is_reserved
            or any(ip in prefix for prefix in IPV6_TRANSLATION_PREFIXES)
        ):
            raise ValueError("The target resolves to a private or reserved address and cannot be scanned.")
    return Target(url=parsed.geturl(), hostname=hostname, port=port, addresses=addresses)


def _tls_finding(target: Target) -> list[dict]:
    if not target.url.startswith("https://"):
        return [_finding("Transport", "HTTPS is not used", "high", f"Target URL uses {urlparse(target.url).scheme.upper()}.", "Traffic and session cookies may be exposed or modified in transit when a site is served without HTTPS.", "Serve the application over HTTPS and redirect all HTTP traffic to its HTTPS equivalent.", "Moderate")]
    try:
        context = ssl.create_default_context()
        with (
            socket.create_connection(
                (target.addresses[0], target.port), timeout=settings.scan_timeout_seconds
            ) as raw,
            context.wrap_socket(raw, server_hostname=target.hostname) as secured,
        ):
            certificate = secured.getpeercert()
        if not certificate:
            return [_finding("Transport", "TLS certificate could not be verified", "high", "No peer certificate was returned.", "An unverified certificate prevents reliable encrypted connections.", "Install a valid certificate with a complete trust chain.", "Moderate")]
    except (OSError, ssl.SSLError) as error:
        return [_finding("Transport", "TLS connection validation failed", "high", str(error), "Users may receive certificate warnings or be unable to establish a secure connection.", "Correct the certificate, hostname, and TLS configuration before deployment.", "Moderate")]
    return []


def inspect_url(target: Target) -> list[dict]:
    findings = _tls_finding(target)
    headers: dict[str, str] = {}
    body = ""
    try:
        transport = _PinnedHTTPTransport(target)
        with httpx.Client(
            transport=transport,
            trust_env=False,
            timeout=settings.scan_timeout_seconds,
            follow_redirects=False,
            max_redirects=0,
            headers={"User-Agent": "Valorynn-Authorized-Scanner/0.1"},
        ) as client:
            response = client.get(target.url)
        headers = {key.lower(): value for key, value in response.headers.items()}
        body = response.text[:250_000]
        if response.is_redirect:
            findings.append(_finding("Configuration", "Redirect requires review", "low", f"HTTP {response.status_code} redirects to {response.headers.get('location', 'an unspecified location')}.", "Redirects can unintentionally downgrade transport or expose users to an unexpected destination.", "Confirm redirects stay on HTTPS and trusted domains.", "Easy"))
    except (httpx.HTTPError, UnicodeError) as error:
        findings.append(_finding("Availability", "Target could not be assessed", "medium", str(error), "A controlled request did not complete within the assessment limits, so results are incomplete.", "Confirm the authorized target is publicly reachable, then re-scan.", "Easy"))
        return findings

    required_headers = {
        "strict-transport-security": ("HSTS header is missing", "medium", "Without HSTS, browsers may be vulnerable to a first-visit HTTP downgrade.", "Set Strict-Transport-Security after confirming HTTPS is deployed everywhere."),
        "content-security-policy": ("Content-Security-Policy header is missing", "medium", "Without CSP, injected scripts have fewer browser-level restrictions.", "Add a restrictive Content-Security-Policy and tune it for application resources."),
        "x-content-type-options": ("X-Content-Type-Options header is missing", "low", "Browsers may MIME-sniff content in risky ways.", "Set X-Content-Type-Options: nosniff."),
        "referrer-policy": ("Referrer-Policy header is missing", "low", "URLs or query data can be sent to third-party destinations as referrer data.", "Set a suitable Referrer-Policy such as strict-origin-when-cross-origin."),
        "permissions-policy": ("Permissions-Policy header is missing", "low", "Browser features may be available more broadly than needed.", "Set Permissions-Policy to disable unneeded browser capabilities."),
    }
    for name, (title, severity, explanation, remediation) in required_headers.items():
        if name not in headers:
            findings.append(_finding("Security headers", title, severity, f"Response did not include {name}.", explanation, remediation, "Easy"))
    for cookie in [value.lower() for key, value in headers.items() if key == "set-cookie"]:
        if target.url.startswith("https://") and "secure" not in cookie:
            findings.append(_finding("Cookies", "Cookie missing Secure flag", "medium", cookie, "A session cookie without Secure can be sent over an unencrypted connection.", "Set the Secure attribute on all cookies used over HTTPS.", "Easy"))
        if "httponly" not in cookie:
            findings.append(_finding("Cookies", "Cookie missing HttpOnly flag", "medium", cookie, "JavaScript could read a cookie that may carry session state.", "Set HttpOnly on session and other non-JavaScript cookies.", "Easy"))
        if "samesite" not in cookie:
            findings.append(_finding("Cookies", "Cookie missing SameSite attribute", "low", cookie, "Cross-site requests may carry the cookie unexpectedly.", "Set SameSite=Lax or Strict when compatible with the sign-in flow.", "Easy"))
    server = headers.get("server", "")
    powered_by = headers.get("x-powered-by", "")
    if re.search(r"(?:debug|development|werkzeug|express)", f"{server} {powered_by}", re.I) or "traceback" in body.lower():
        findings.append(_finding("Exposure", "Debug or framework information exposed", "medium", f"Server headers: {server or 'none'}; X-Powered-By: {powered_by or 'none'}.", "Framework and debug details help attackers tailor attacks and can expose sensitive implementation data.", "Disable debug mode and remove unnecessary technology headers.", "Easy"))
    cors = headers.get("access-control-allow-origin", "")
    if cors.strip() == "*":
        findings.append(_finding("Vibe-coded app mode", "Overly broad CORS policy", "medium", "Access-Control-Allow-Origin: *", "Any web origin may make browser requests to endpoints allowed by this response.", "Allow only known frontend origins and avoid wildcard CORS for authenticated resources.", "Easy"))
    return findings


def inspect_source(source: bytes, filename: str) -> list[dict]:
    """Inspect a bounded ZIP in memory; it is never written to disk or database."""
    findings: list[dict] = []
    if len(source) > settings.max_source_bytes:
        return [_finding("Source review", "Source upload not inspected", "info", f"{filename} exceeds the {settings.max_source_bytes} byte limit.", "The upload was not retained or unpacked to protect the service.", "Upload a smaller, scoped archive for source review.", "Easy", "source-review")]
    try:
        archive = zipfile.ZipFile(BytesIO(source))
        entries = [entry for entry in archive.infolist() if not entry.is_dir()]
        if len(entries) > 500 or sum(entry.file_size for entry in entries) > 20 * 1024 * 1024:
            raise ValueError("Archive has too many or too-large uncompressed entries")
    except (zipfile.BadZipFile, ValueError) as error:
        return [_finding("Source review", "Source archive could not be reviewed", "info", str(error), "Only small ZIP archives are reviewed in-memory to limit risk and protect uploaded code.", "Upload a valid, scoped ZIP archive.", "Easy", "source-review")]

    text_parts: list[str] = []
    manifest_dependencies: list[str] = []
    for entry in entries:
        if entry.file_size > 500_000 or ".." in entry.filename.replace("\\", "/").split("/"):
            continue
        try:
            raw = archive.read(entry)[:500_000]
            content = raw.decode("utf-8", errors="ignore")
        except (OSError, RuntimeError):
            continue
        text_parts.append(f"\n/* {entry.filename} */\n{content}")
        if entry.filename.endswith("package.json"):
            try:
                package = json.loads(content)
                manifest_dependencies.extend(list(package.get("dependencies", {}).keys()))
            except json.JSONDecodeError:
                pass
    corpus = "".join(text_parts)[:2_000_000]
    for pattern, title in SECRET_PATTERNS:
        match = pattern.search(corpus)
        if match:
            findings.append(_finding("Secrets", title, "high", f"Pattern found near: {match.group(0)[:40]}…", "Secrets placed in source can be copied from repositories, bundles, or browser code. The detected value is deliberately redacted.", "Revoke any exposed credential, move it to server-side environment variables, and add secret scanning to CI.", "Moderate", "source-review"))
    if DEBUG_PATTERN.search(corpus):
        findings.append(_finding("Configuration", "Development configuration in source", "medium", "Development/debug configuration marker found.", "Development settings can disclose errors, weaken security, or enable unsafe behavior in production.", "Use environment-specific production configuration and keep debug features disabled.", "Easy", "source-review"))
    if CORS_PATTERN.search(corpus):
        findings.append(_finding("Vibe-coded app mode", "Wildcard CORS configured in source", "medium", "A wildcard Access-Control-Allow-Origin configuration was found.", "A permissive CORS setting may expose browser-accessible endpoints to untrusted origins.", "Restrict CORS to documented, trusted origins; test authenticated flows.", "Easy", "source-review"))
    if re.search(r"(?:firebaseConfig|createClient\([^)]*supabase)", corpus, re.I):
        findings.append(_finding("Vibe-coded app mode", "Firebase or Supabase configuration requires review", "medium", "Client backend configuration reference found.", "Client configuration is not automatically insecure, but permissive database/storage rules or a service-role key would create serious exposure.", "Review Firebase/Supabase rules, ensure server-only keys never reach the client, and test unauthenticated access.", "Moderate", "source-review"))
    if UPLOAD_PATTERN.search(corpus) and not re.search(r"(?:fileFilter|mimetype|content-type|sizeLimit|maxFileSize)", corpus, re.I):
        findings.append(_finding("Vibe-coded app mode", "File-upload validation not evident", "medium", "Upload-related source was found without a nearby validation control pattern.", "Unrestricted uploads can allow oversized, executable, or unsafe content.", "Validate file type and size server-side, rename uploads, and store outside executable paths.", "Moderate", "source-review"))
    if re.search(r"(?:app\.(?:get|post|put|delete)|router\.(?:get|post)|@app\.(?:get|post))", corpus, re.I) and not re.search(r"(?:auth|authorize|require_user|verify_token|session)", corpus, re.I):
        findings.append(_finding("Vibe-coded app mode", "Authentication or authorization not evident", "high", "Route definitions were found without a recognizable access-control pattern.", "Public routes are not necessarily wrong, but sensitive functions need server-enforced authentication and ownership checks.", "Map every route to an access rule; enforce authentication and object-level authorization on the server.", "Advanced", "source-review"))
    if manifest_dependencies:
        findings.append(_finding("Dependencies", "Dependency manifest discovered", "info", f"Found {len(manifest_dependencies)} declared dependencies in package.json.", "This version records the manifest; vulnerability matching should use an authoritative lockfile/SBOM and CVE feed.", "Run the included NVD model training and integrate a CVE feed or package audit in the next scanner iteration.", "Moderate", "source-review"))
    return findings


def execute_scan(scan_id: int, source_bytes: bytes | None = None, source_filename: str | None = None) -> None:
    # Workers obtain only the needed target directly; all user-facing reads enforce ownership.
    from app.database import one
    row = one("SELECT s.id, a.target_url FROM scans s JOIN applications a ON a.id=s.application_id WHERE s.id=?", (scan_id,))
    if not row:
        return
    update_scan(scan_id, status="running", started_at=utcnow())
    try:
        target = validate_target(row["target_url"])
        findings = inspect_url(target)
        if source_bytes and source_filename:
            findings.extend(inspect_source(source_bytes, source_filename))
        score, risk, summary = calculate_score(findings)
        insert_findings(scan_id, findings)
        update_scan(scan_id, status="completed", completed_at=utcnow(), score=score, risk_level=risk, summary=summary)
    except Exception as error:  # Errors are stored for the owner, never surfaced as a stack trace.
        update_scan(scan_id, status="failed", completed_at=utcnow(), error_message=str(error)[:500])
