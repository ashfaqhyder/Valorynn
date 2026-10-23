"""Evidence-aware, beginner-friendly remediation guidance for scanner findings."""
from __future__ import annotations

from typing import Any


def _rule(
    simple: str,
    observation: str,
    why: str,
    steps: tuple[str, ...],
    verification: str,
    ask_developer: str,
    priority: str,
    references: tuple[tuple[str, str], ...] = (),
    example: str | None = None,
    evidence_kind: str = "observed",
) -> dict[str, Any]:
    return {
        "simple_explanation": simple,
        "what_scanner_observed": observation,
        "why_it_matters": why,
        "steps": steps,
        "verification": verification,
        "ask_developer": ask_developer,
        "priority": priority,
        "references": references,
        "example": example,
        "evidence_kind": evidence_kind,
    }


_OWASP_TLS = ("OWASP: Transport Layer Security Cheat Sheet", "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html")
_OWASP_UPLOAD = ("OWASP: File Upload Cheat Sheet", "https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html")
_OWASP_ACCESS = ("OWASP: Authorization Cheat Sheet", "https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html")
_OWASP_SECRETS = ("OWASP: Secrets Management Cheat Sheet", "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html")


GUIDANCE_BY_RULE: dict[tuple[str, str], dict[str, Any]] = {
    ("Transport", "HTTPS is not used"): _rule(
        "The scanned address uses HTTP, which does not encrypt the connection.",
        "The target URL scheme observed by the scanner was HTTP.",
        "Network observers may be able to read or alter traffic. This check does not establish that sensitive data was transmitted.",
        (
            "Enable HTTPS with a certificate issued for the target hostname.",
            "Configure the hosting platform or web server to serve the application over HTTPS.",
            "After HTTPS works, redirect HTTP requests to the same HTTPS hostname.",
            "Update application links and callbacks to use HTTPS.",
        ),
        "Open the HTTPS URL and confirm the browser reports a valid certificate. Re-scan and confirm this finding is absent; test that HTTP redirects to HTTPS.",
        "Please enable HTTPS for this hostname, then set up an HTTP-to-HTTPS redirect without changing the application path.",
        "High",
        (_OWASP_TLS,),
        "server {\n    listen 80;\n    server_name example.com;\n    return 301 https://$host$request_uri;\n}",
    ),
    ("Transport", "TLS certificate could not be verified"): _rule(
        "The scanner did not receive a certificate it could verify for this TLS connection.",
        "The TLS probe returned no peer certificate.",
        "Browsers and clients may refuse the connection or show a certificate warning. The scanner did not verify what a browser would show on every device.",
        (
            "Confirm the certificate is installed on the service listening at the target hostname and port.",
            "Install the complete certificate chain from a trusted certificate authority.",
            "Check that the certificate names the requested hostname and is within its validity period.",
            "Keep certificate verification enabled; do not replace the certificate with a self-signed certificate for public use.",
        ),
        "Verify the endpoint presents a currently valid certificate chain for the requested hostname, then re-scan.",
        "Ask your hosting provider to check the certificate chain, hostname, and expiry for this exact host and port.",
        "High",
        (_OWASP_TLS,),
    ),
    ("Transport", "TLS connection validation failed"): _rule(
        "The scanner could not complete or validate its TLS probe.",
        "The evidence contains the connection or TLS error returned by the scanner.",
        "A TLS configuration problem can prevent clients from establishing a trusted encrypted connection. This probe failure alone does not prove every client is affected.",
        (
            "Use the recorded error to identify whether the service refused the connection, timed out, or presented a certificate problem.",
            "Confirm the HTTPS service is listening on the target port.",
            "Check the hostname, certificate chain, expiry, and supported TLS configuration.",
            "Retest with a standard browser or TLS diagnostic after the change.",
        ),
        "After correcting the reported TLS problem, verify the HTTPS endpoint with a standard client and re-scan.",
        "Please investigate the exact TLS error shown in the report for this host and port; retain certificate verification.",
        "High",
        (_OWASP_TLS,),
    ),
    ("Configuration", "Redirect requires review"): _rule(
        "The server returned a redirect, but Valorynn did not follow it.",
        "The report records the redirect status and Location value when provided. Its destination was not requested.",
        "The final destination and its security settings remain unverified. A redirect may be intentional; this finding does not establish that it is unsafe.",
        (
            "Confirm the Location destination is expected and remains within your intended service boundary.",
            "Prefer an HTTPS destination and avoid redirecting users to an untrusted host.",
            "Check that the destination applies the expected authentication and security controls.",
            "Run a separately authorized assessment for the destination if it is in scope.",
        ),
        "Manually confirm the destination and its HTTPS configuration; Valorynn deliberately does not follow redirects.",
        "Please confirm whether this redirect is intended, identify the final destination, and arrange an authorized check of that destination.",
        "Medium",
        (("MDN: Redirections in HTTP", "https://developer.mozilla.org/en-US/docs/Web/HTTP/Redirections"),),
        evidence_kind="partial",
    ),
    ("Configuration", "Development configuration in source"): _rule(
        "A development or debug configuration marker was found in the supplied source archive.",
        "The source heuristic matched a development/debug marker; the report does not include a file path or line number.",
        "If such a setting is active in production it may expose diagnostics or weaken protections. A text match does not prove the setting is active or reachable.",
        (
            "Locate the matched setting in the original source and determine whether it is used in production.",
            "Set production configuration explicitly through the deployment environment.",
            "Disable debug mode in production and avoid returning stack traces to users.",
            "Keep development settings limited to local or non-production environments.",
        ),
        "Review the deployed production configuration and confirm that debug behavior is disabled.",
        "Please locate the matching configuration in the source and confirm the deployed production value is safe.",
        "Medium",
        (("OWASP: Web Security Testing Guide", "https://owasp.org/www-project-web-security-testing-guide/"),),
        evidence_kind="heuristic",
    ),
    ("Availability", "Target could not be assessed"): _rule(
        "The scanner could not finish its controlled request, so this assessment is incomplete.",
        "The evidence contains the HTTPX or decoding error observed during the request.",
        "The missing response means response-header and body checks may not have run. It is not evidence by itself that the target is vulnerable or unavailable to all users.",
        (
            "Check whether the target is reachable from your normal network and whether it requires access controls.",
            "Confirm the service accepts the requested HTTP or HTTPS connection on the configured port.",
            "Review the recorded error for timeout, TLS, protocol, or response-encoding clues.",
            "Re-run the authorized scan after the service is reachable; review the coverage status before relying on its results.",
        ),
        "A successful authorized re-scan should complete the configured URL checks; this result remains incomplete until then.",
        "Please check the reported connection error and confirm the service is available to the scanner; no finding should be treated as cleared until a successful re-scan.",
        "Medium",
        (),
        evidence_kind="partial",
    ),
    ("Assessment coverage", "Response body inspection incomplete"): _rule(
        "Valorynn did not inspect the full response body, so content-based checks may be missing findings.",
        "The evidence explains whether the body was truncated at the configured byte cap, encoded, or not inspected due to a redirect.",
        "An uninspected portion could contain relevant content, but this scanner does not claim that it does. Header findings may still be based on the observed response.",
        (
            "Review the stated reason for incomplete inspection and the response size or encoding configuration.",
            "If safe and necessary, inspect the endpoint with an approved tool that has appropriate resource limits.",
            "For a redirect, assess the destination separately after confirming authorization.",
            "Re-run the assessment and confirm the report no longer marks inspection incomplete.",
        ),
        "Re-scan after the cause is addressed and confirm the coverage status no longer reports incomplete inspection.",
        "Please review the incomplete-inspection reason and decide whether a separately authorized, bounded review of the endpoint is needed.",
        "Medium",
        (),
        evidence_kind="partial",
    ),
    ("Assessment coverage", "Source archive content not fully inspected"): _rule(
        "Some uploaded source content was intentionally skipped or fell beyond the source-text inspection cap.",
        "The evidence reports the number of skipped archive entries and/or that combined text exceeded the configured character limit.",
        "Heuristic source checks only considered inspected text. The omitted content might be irrelevant or might contain additional signals; Valorynn makes no claim either way.",
        (
            "Review the evidence to see whether entries were skipped, the combined text limit was reached, or both.",
            "Create a smaller archive with relevant application source and configuration files; avoid generated assets and unnecessary binaries.",
            "If specific skipped content matters, have a developer review it directly in a trusted environment.",
            "Run another source review and confirm this coverage finding is absent before treating the supplied archive review as complete.",
        ),
        "Re-run source review on a focused archive and confirm that all intended source content is within the scanner's limits.",
        "Please check which archive content was omitted and prepare a smaller, relevant archive or review the omitted files directly.",
        "Low",
        (),
        evidence_kind="partial",
    ),
}

_HEADER_GUIDANCE = {
    "HSTS header is missing": (
        "Strict-Transport-Security",
        "Configure the HTTPS service to return a Strict-Transport-Security header. Only enable HSTS after HTTPS is working for the hostname.",
        "Verify the HTTPS response includes a valid Strict-Transport-Security value, then re-scan.",
        "Please enable HSTS for the HTTPS host after confirming all required pages support HTTPS.",
        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security",
        "Strict-Transport-Security: max-age=31536000",
    ),
    "Content-Security-Policy header is missing": (
        "Content-Security-Policy",
        "Create a policy matching the application's actual scripts, styles, images, and connections. Start in report-only mode if available, review violations, then enforce it.",
        "Verify the HTTPS response includes the intended Content-Security-Policy header and that key application flows still work.",
        "Please propose a restrictive CSP based on the resources this application actually uses, test it, and then enforce it.",
        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy",
        "Content-Security-Policy: default-src 'self'; object-src 'none'; base-uri 'self'",
    ),
    "X-Content-Type-Options header is missing": (
        "X-Content-Type-Options",
        "Add the response header X-Content-Type-Options: nosniff to prevent browsers from guessing a different content type.",
        "Verify the response includes X-Content-Type-Options: nosniff and confirm assets have correct Content-Type values.",
        "Please configure the web server or application to return X-Content-Type-Options: nosniff.",
        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options",
        "X-Content-Type-Options: nosniff",
    ),
    "Referrer-Policy header is missing": (
        "Referrer-Policy",
        "Choose a policy appropriate for the application; strict-origin-when-cross-origin is a common starting point.",
        "Verify the response includes the chosen Referrer-Policy and test links to external sites for expected referrer behavior.",
        "Please set a Referrer-Policy that limits unnecessary URL detail when users navigate away.",
        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy",
        "Referrer-Policy: strict-origin-when-cross-origin",
    ),
    "Permissions-Policy header is missing": (
        "Permissions-Policy",
        "Identify browser features the application needs and explicitly restrict unused features with a suitable Permissions-Policy.",
        "Verify the response includes the selected policy and that required browser features continue to work.",
        "Please review which browser features are needed and configure a least-privilege Permissions-Policy.",
        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy",
        "Permissions-Policy: camera=(), microphone=(), geolocation=()",
    ),
}

for _title, (_header, _advice, _verify, _ask, _url, _example) in _HEADER_GUIDANCE.items():
    GUIDANCE_BY_RULE[("Security headers", _title)] = _rule(
        f"The observed response did not include the {_header} security header.",
        f"The scanner did not find the {_header} header in the received response.",
        "This header can provide a browser-side security control. Its absence alone does not prove an exploitable vulnerability; the effect depends on the application and browser behavior.",
        (_advice,),
        _verify,
        _ask,
        "Medium" if _header in {"Strict-Transport-Security", "Content-Security-Policy"} else "Low",
        (("MDN: " + _header, _url),),
        _example,
        evidence_kind="observed",
    )

GUIDANCE_BY_RULE.update(
    {
        ("Cookies", "Cookie missing Secure flag"): _rule(
            "A Set-Cookie response did not include the Secure attribute on an HTTPS target.",
                "The observed Set-Cookie value is shown in the evidence; the scanner uses a simple case-insensitive text check for 'secure', not a full cookie-attribute parser.",
            "Without Secure, a browser may send the cookie over an unencrypted HTTP connection. The evidence does not establish whether the cookie contains session data or whether HTTP is reachable.",
            (
                "Identify the cookie and whether it contains authentication or other sensitive state.",
                "Set Secure on cookies that should only travel over HTTPS.",
                "Keep HTTPS enforced across the site and review any HTTP endpoints.",
            ),
            "Verify the cookie's Set-Cookie response includes Secure, then test the sign-in flow and re-scan.",
            "Please add Secure to the affected cookie and confirm the application works only over HTTPS.",
            "High",
            (("MDN: Set-Cookie", "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie"),),
            "Set-Cookie: <name>=<value>; Path=/; Secure; HttpOnly; SameSite=Lax",
        ),
        ("Cookies", "Cookie missing HttpOnly flag"): _rule(
            "A Set-Cookie response did not include HttpOnly.",
                "The observed Set-Cookie value is shown in the evidence; the scanner uses a simple case-insensitive text check for 'httponly', not a full cookie-attribute parser.",
            "Without HttpOnly, browser scripts can read the cookie. This matters especially for authentication cookies; the scanner cannot determine the cookie's purpose from this flag alone.",
            (
                "Identify whether application JavaScript needs to read this cookie.",
                "For session or other non-script cookies, set HttpOnly.",
                "If JavaScript access is required, document why and use other protections for the value.",
            ),
            "Verify the relevant Set-Cookie response includes HttpOnly, and test the affected user flow.",
            "Please determine whether the cookie is session-related and set HttpOnly unless client-side code genuinely requires access.",
            "Medium",
            (("MDN: Set-Cookie", "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie"),),
            "Set-Cookie: <name>=<value>; Path=/; HttpOnly",
        ),
        ("Cookies", "Cookie missing SameSite attribute"): _rule(
            "A Set-Cookie response did not include SameSite.",
                "The observed Set-Cookie value is shown in the evidence; the scanner uses a simple case-insensitive text check for 'samesite', not a full cookie-attribute parser.",
            "SameSite controls when browsers attach cookies to cross-site requests. The appropriate value depends on the application's sign-in and navigation flows.",
            (
                "Review whether the cookie is required for cross-site sign-in or embedded flows.",
                "Use SameSite=Lax or Strict when compatible; use None only when cross-site use is required and pair it with Secure.",
                "Test login, logout, and any federated sign-in flow after changing the setting.",
            ),
            "Verify the Set-Cookie response includes the selected SameSite value and test sign-in flows.",
            "Please choose a SameSite value that fits the application's sign-in flow and test it before deployment.",
            "Low",
            (("MDN: Set-Cookie", "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie"),),
            "Set-Cookie: <name>=<value>; Path=/; SameSite=Lax",
        ),
    }
)

_CORS_DOC = ("MDN: CORS", "https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS")
GUIDANCE_BY_RULE.update(
    {
        ("Exposure", "Debug or framework information exposed"): _rule(
            "The response contained a debug/framework indicator or the inspected body contained the word traceback.",
            "The evidence includes Server and X-Powered-By header values; the body check is a simple text match and is not retained in the evidence.",
            "Detailed framework information can help someone understand the service. A header or text match does not prove debug mode is enabled or that sensitive details were disclosed.",
            (
                "Review the recorded headers and the endpoint's response in your normal application environment.",
                "Disable production debug pages and avoid exposing stack traces to visitors.",
                "Remove unnecessary technology-identifying headers where practical.",
            ),
            "Verify production errors show a generic user-facing message and that unnecessary identifying headers are absent; re-scan.",
            "Please confirm whether the recorded header or response match is expected, and disable production debug output if present.",
            "Medium",
            (("OWASP: Error Handling Cheat Sheet", "https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html"),),
            evidence_kind="heuristic",
        ),
        ("Vibe-coded app mode", "Overly broad CORS policy"): _rule(
            "The response advertised Access-Control-Allow-Origin: *.",
            "The scanner observed the wildcard Access-Control-Allow-Origin response header.",
            "Any website may be allowed to read responses that browsers consider CORS-shareable. This does not by itself allow access to authenticated data or prove a sensitive endpoint is exposed.",
            (
                "List the specific browser origins that need cross-origin access.",
                "Return only those trusted origins instead of * where access is restricted.",
                "Do not combine wildcard origins with credentialed requests; configure credentials and allowed origins deliberately.",
                "Test preflight and application API flows from both allowed and unallowed origins.",
            ),
            "Test from an allowed and an unallowed browser origin, confirming the unallowed origin cannot read protected responses.",
            "Please replace the wildcard with the exact trusted frontend origins and test that unrelated sites cannot read protected responses.",
            "Medium",
            (_CORS_DOC, ("OWASP: CORS", "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Origin_Resource_Sharing_Cheat_Sheet.html")),
            "Access-Control-Allow-Origin: https://app.example.com",
            evidence_kind="observed",
        ),
        ("Vibe-coded app mode", "Wildcard CORS configured in source"): _rule(
            "The supplied source archive contains a wildcard CORS configuration match.",
            "A source-text heuristic found a wildcard Access-Control-Allow-Origin pattern; no file path or line is recorded.",
            "If this configuration is active for sensitive endpoints, browsers may be allowed to read responses cross-origin. The match does not prove the setting is active or that sensitive data is available.",
            (
                "Locate the match in the original source and confirm whether it is used by the deployed application.",
                "Replace the wildcard with an explicit allowlist where endpoints contain restricted data.",
                "Test from allowed and unallowed browser origins, including credentialed requests.",
            ),
            "Review the deployed response from allowed and unallowed origins after confirming the source configuration.",
            "Please locate the source match, confirm whether it is deployed, and restrict it if the endpoint serves non-public data.",
            "Medium",
            (_CORS_DOC,),
            evidence_kind="heuristic",
        ),
        ("Vibe-coded app mode", "Firebase or Supabase configuration requires review"): _rule(
            "The source contains a client-side Firebase or Supabase configuration reference that needs a rules review.",
            "A source-text heuristic found a configuration reference; it did not test database rules, storage rules, or credential validity.",
            "Client configuration may be expected. Risk depends on server-side access rules and whether privileged credentials are exposed; this finding does not establish either.",
            (
                "Review database and storage access rules in the provider console.",
                "Require server-side authorization or row-level security for non-public records.",
                "Keep service-role or administrative credentials on trusted servers and rotate them if exposure is confirmed.",
                "Test representative unauthenticated and low-privilege access paths.",
            ),
            "Verify provider-side rules with authorized test accounts and confirm no privileged credential is present in client-delivered assets.",
            "Please review the provider's access rules and confirm no administrative key is included in browser-delivered code.",
            "High",
            (("Firebase: Security Rules", "https://firebase.google.com/docs/rules"), ("Supabase: Row Level Security", "https://supabase.com/docs/guides/database/postgres/row-level-security")),
            evidence_kind="heuristic",
        ),
        ("Vibe-coded app mode", "File-upload validation not evident"): _rule(
            "The source contains upload-related text, but the scanner did not recognize its limited set of validation markers.",
            "A source-text heuristic did not find nearby patterns such as fileFilter, mimetype, sizeLimit, or maxFileSize. This is not a complete code analysis.",
            "If uploads lack server-side controls, oversized or unsafe files may create risk. The scanner has not confirmed that validation is absent.",
            (
                "Locate the upload handler and verify file size and permitted type on the server.",
                "Do not trust the browser-provided filename or Content-Type; inspect content where appropriate.",
                "Store uploads outside executable paths and use generated storage names.",
                "Test rejected oversized and disallowed files in a safe test environment.",
            ),
            "In a safe test environment, verify invalid and oversized uploads are rejected before storage.",
            "Please locate the upload handler and show how the server rejects oversized and disallowed files before storing them.",
            "Medium",
            (_OWASP_UPLOAD,),
            evidence_kind="heuristic",
        ),
        ("Vibe-coded app mode", "Authentication or authorization not evident"): _rule(
            "The source contains route definitions but the scanner did not recognize its limited set of authentication markers.",
            "A source-text heuristic matched route patterns and did not find known auth-related terms. It did not inspect runtime behavior or every route.",
            "Sensitive routes need server-side access checks. Public routes may be intentional, and this heuristic does not prove that authorization is missing.",
            (
                "List routes that expose private data or change account state.",
                "Verify authentication is enforced on those routes by the server, not only by the interface.",
                "Check object ownership and role permissions for every requested record.",
                "Test anonymous, regular-user, and authorized-owner access in a non-production test environment.",
            ),
            "Test anonymous, ordinary-user, and owner permissions for representative sensitive routes after changes.",
            "Please review private and write-capable routes and demonstrate server-side authentication and ownership checks for each.",
            "High",
            (_OWASP_ACCESS,),
            evidence_kind="heuristic",
        ),
    }
)

GUIDANCE_BY_RULE.update(
    {
        ("Source review", "Source upload not inspected"): _rule(
            "The uploaded source archive exceeded the configured size limit and was not inspected.",
            "The evidence records the archive name and configured byte limit. The archive was not unpacked for this scan.",
            "No conclusion can be drawn about source-code findings in this archive because it was not reviewed.",
            (
                "Create a smaller archive containing only relevant source and configuration files.",
                "Remove generated assets and dependencies if they are not needed for review.",
                "Upload the smaller archive for a new authorized source review.",
            ),
            "A new scan should report source review findings or explicitly state that source inspection could not be completed.",
            "Please prepare a smaller source archive without secrets or generated files and upload it for review.",
            "Low",
            (),
            evidence_kind="partial",
        ),
        ("Source review", "Source archive could not be reviewed"): _rule(
            "Valorynn could not open or safely review the supplied source archive.",
            "The evidence contains the ZIP parsing or configured archive-limit error.",
            "Source checks did not complete for this archive. This says nothing about whether the project itself is secure or insecure.",
            (
                "Confirm the upload is a valid ZIP archive and is not corrupted.",
                "Keep the archive within the upload, entry-count, and uncompressed-size limits.",
                "Remove unnecessary generated or binary files and retry with a focused archive.",
            ),
            "A new scan should show that the archive opened and was inspected within configured limits.",
            "Please create a valid, focused ZIP archive within the stated limits and upload it for a new review.",
            "Low",
            (),
            evidence_kind="partial",
        ),
        ("Dependencies", "Dependency manifest discovered"): _rule(
            "The source review found dependency names in a package.json manifest; it did not identify vulnerable versions.",
            "The evidence reports how many dependency names were read. No lockfile-based vulnerability matching or CVE check is performed by this finding.",
            "Outdated or vulnerable packages are possible in any dependency set, but this scan has not established that any listed package is affected.",
            (
                "Review the project's lockfile and update it using the package manager.",
                "Run the package manager's audit or an approved Software Composition Analysis tool against the lockfile.",
                "Review advisories and compatibility before updating production dependencies.",
                "Re-run dependency analysis after updates and keep the lockfile in version control.",
            ),
            "Review the audit output for applicable advisories and verify the resolved lockfile after approved updates.",
            "Please run an approved dependency audit against the lockfile and share any actionable advisories; this finding alone is not a vulnerability report.",
            "Low",
            (("npm: npm audit", "https://docs.npmjs.com/cli/commands/npm-audit"),),
            evidence_kind="observed",
        ),
    }
)

for _title in (
    "Potential hard-coded secret",
    "Potential Firebase API key",
    "Potential Supabase service-role secret",
):
    GUIDANCE_BY_RULE[("Secrets", _title)] = _rule(
        "A source-text pattern matched a value that may be a credential or key; Valorynn did not validate it.",
        "The report contains a deliberately redacted sample of the matched text. No full credential value is stored in this finding.",
        "If the value is an active secret and is accessible to untrusted users, it may permit unauthorized use. The scanner does not prove validity, privilege, or exposure.",
        (
            "Have an authorized developer locate the value in the original source and determine whether it is a real credential.",
            "If valid, revoke or rotate it with the service provider before removing it from the source.",
            "Move server-side secrets to a protected secret manager or environment configuration.",
            "Review repository history and deployment artifacts; removing a current copy does not invalidate an already-issued key.",
            "Add secret detection to code review or CI and verify that client-side configuration contains no privileged key.",
        ),
        "Confirm the value is invalid or rotate it, remove it from active source, and re-scan. Do not paste the full value into tickets or chat.",
        "Please verify whether the redacted match is a real credential. If it is, rotate it first, remove it from source, and review access logs with the provider.",
        "High",
        (_OWASP_SECRETS,),
        evidence_kind="heuristic",
    )


def guidance_for(finding: dict[str, Any]) -> dict[str, Any]:
    """Return presentation guidance without altering the persisted finding or score."""
    key = (finding.get("category", ""), finding.get("title", ""))
    rule = GUIDANCE_BY_RULE.get(key)
    if rule is None:
        rule = _rule(
            "This finding has no category-specific remediation entry yet.",
            "No additional scanner evidence is available beyond the recorded finding fields.",
            "The recorded finding should be reviewed, but this report does not infer an unsupported vulnerability class.",
            (
                "Review the recorded title, evidence, explanation, and source with a qualified developer.",
                "Confirm whether the observation applies to the deployed application.",
                "Define a narrowly scoped correction based on that confirmation.",
            ),
            "Re-run the same authorized assessment and confirm the original observation is no longer present; a recommendation alone is not proof of resolution.",
            "Please ask a developer to review the finding evidence and confirm whether it applies to the deployed system.",
            "Review",
            (),
            evidence_kind="unverified",
        )
    result = dict(rule)
    result["steps"] = list(rule["steps"])
    result["references"] = [{"label": label, "url": url} for label, url in rule["references"]]
    result["example"] = rule["example"]
    result["effort"] = finding.get("effort") or "Not recorded"
    result["evidence"] = finding.get("evidence") or "No evidence was recorded; this observation is unverified."
    result["evidence_kind"] = (
        rule["evidence_kind"]
        if finding.get("evidence")
        else "unverified"
    )
    result["evidence_label"] = {
        "observed": "Observed by scanner",
        "heuristic": "Heuristic source match; confirm manually",
        "partial": "Partial assessment",
        "unverified": "Unverified; no evidence recorded",
    }[result["evidence_kind"]]
    result["technical_details"] = {
        "category": finding.get("category") or "Unknown",
        "source": finding.get("source") or "Not recorded",
        "confidence": finding.get("confidence"),
        "location_note": (
            "The scanner does not record source file paths or line numbers for this finding."
            if finding.get("source") == "source-review"
            else "The affected component is described only by the target URL and recorded response evidence."
        ),
    }
    return result


def enrich_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Copy findings and attach guidance for display; never change stored score fields."""
    return [{**finding, "guidance": guidance_for(finding)} for finding in findings]


def assessment_status(scan: dict[str, Any], findings: list[dict[str, Any]]) -> tuple[str, str]:
    """Describe scan coverage without treating a completed worker as full assurance."""
    incomplete_categories = {
        "Assessment coverage",
        "Availability",
    }
    incomplete_titles = {
        "Redirect requires review",
        "Source upload not inspected",
        "Source archive could not be reviewed",
    }
    incomplete = any(
        item.get("category") in incomplete_categories
        or item.get("title") in incomplete_titles
        for item in findings
    ) or str(scan.get("summary") or "").lower().startswith("incomplete assessment")
    if incomplete:
        return (
            "Incomplete",
            "One or more requested checks did not fully complete. Treat uninspected areas as unknown, not as clear.",
        )
    return (
        "Completed within configured checks",
        "The configured checks completed, but this limited assessment cannot prove the application is free of security issues.",
    )


def report_overview(scan: dict[str, Any], findings: list[dict[str, Any]]) -> dict[str, Any]:
    status, limitation = assessment_status(scan, findings)
    actionable = [
        finding for finding in findings
        if finding.get("severity") in {"critical", "high", "medium"}
    ]
    ordered = sorted(
        actionable,
        key=lambda finding: (
            {"critical": 0, "high": 1, "medium": 2}[finding["severity"]],
            int(finding.get("id") or 0),
        ),
    )
    if actionable:
        summary = (
            f"The assessment recorded {len(findings)} finding(s), including "
            f"{len(actionable)} medium-or-higher item(s). Start with the highest-severity "
            "observations, confirm they apply, then make and verify changes."
        )
    else:
        summary = (
            f"The assessment recorded {len(findings)} finding(s) and no medium-or-higher "
            "items. This means the configured checks did not record higher-priority issues; "
            "it is not proof the application is secure."
        )
    return {
        "status": status,
        "limitation": limitation,
        "executive_summary": summary,
        "key_risks": ordered[:5],
        "verification_note": (
            "A suggested fix is not a verified fix. Only a later assessment with new "
            "evidence can show whether the recorded observation remains."
        ),
    }
