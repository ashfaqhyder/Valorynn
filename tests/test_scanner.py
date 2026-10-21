import socket
import ssl
from unittest.mock import MagicMock, Mock

import httpcore
import httpx
import pytest

from app import scanner
from app.scanner import SECRET_PATTERNS, inspect_source, validate_target

STREAM_CHUNK_BYTES = 16 * 1024


class RepeatingStream(httpx.SyncByteStream):
    def __init__(self, chunk: bytes, max_chunks: int | None = None):
        self.chunk = chunk
        self.max_chunks = max_chunks
        self.chunks_yielded = 0
        self.closed = False

    def __iter__(self):
        while self.max_chunks is None or self.chunks_yielded < self.max_chunks:
            self.chunks_yielded += 1
            yield self.chunk

    def close(self):
        self.closed = True


class FailingStream(httpx.SyncByteStream):
    def __init__(self):
        self.closed = False

    def __iter__(self):
        raise httpx.ReadTimeout("simulated read timeout")
        yield b""

    def close(self):
        self.closed = True


def mock_dns(monkeypatch, addresses):
    def getaddrinfo(hostname, port, *, type):
        return [
            (
                socket.AF_INET6 if ":" in address else socket.AF_INET,
                type,
                socket.IPPROTO_TCP,
                "",
                (address, port, 0, 0) if ":" in address else (address, port),
            )
            for address in addresses
        ]

    monkeypatch.setattr(scanner.socket, "getaddrinfo", getaddrinfo)


def test_validate_target_keeps_mocked_public_addresses(monkeypatch):
    mock_dns(monkeypatch, ["8.8.8.8"])
    target = validate_target("https://scanner.example.test:8443/path")

    assert target.hostname == "scanner.example.test"
    assert target.port == 8443
    assert target.addresses == ("8.8.8.8",)
    assert target.url == "https://scanner.example.test:8443/path"


@pytest.mark.parametrize(
    "addresses",
    [
        ["8.8.8.8", "127.0.0.1"],
        ["8.8.8.8", "::1"],
        ["2001:4860:4860::8888", "fe80::1"],
        ["8.8.8.8", "192.0.2.1"],
        ["64:ff9b::a9fe:a9fe"],
        ["64:ff9b:1::a9fe:a9fe"],
    ],
)
def test_validate_target_rejects_mixed_or_prohibited_dns_answers(monkeypatch, addresses):
    mock_dns(monkeypatch, addresses)
    with pytest.raises(ValueError, match="private or reserved"):
        validate_target("https://scanner.example.test")


def test_validate_target_rejects_localhost_and_private_targets(monkeypatch):
    with pytest.raises(ValueError, match="not permitted|private or reserved"):
        validate_target("http://localhost:8000")

    mock_dns(monkeypatch, ["127.0.0.1"])
    with pytest.raises(ValueError, match="not permitted|private or reserved"):
        validate_target("http://private.example.test:8000")


def test_http_transport_connects_only_to_validated_ip(monkeypatch):
    mock_dns(monkeypatch, ["8.8.8.8"])
    target = validate_target("https://scanner.example.test")
    connected = []

    def refuse_connection(_backend, host, port, **kwargs):
        connected.append((host, port))
        raise httpcore.ConnectError("blocked in regression test")

    monkeypatch.setattr(httpcore.SyncBackend, "connect_tcp", refuse_connection)
    monkeypatch.setattr(scanner, "_tls_finding", lambda _target: [])

    findings = scanner.inspect_url(target)

    assert connected == [("8.8.8.8", 443)]
    assert findings[0]["title"] == "Target could not be assessed"


def test_inspect_url_does_not_follow_redirects(monkeypatch):
    mock_dns(monkeypatch, ["8.8.8.8"])
    target = validate_target("https://scanner.example.test")
    requests = []

    def redirect(request):
        requests.append(request.url)
        return httpx.Response(302, headers={"location": "http://127.0.0.1/admin"})

    monkeypatch.setattr(scanner, "_tls_finding", lambda _target: [])
    monkeypatch.setattr(scanner, "_PinnedHTTPTransport", lambda _target: httpx.MockTransport(redirect))

    findings = scanner.inspect_url(target)

    assert requests == [target.url]
    assert findings[0]["title"] == "Redirect requires review"
    assert any(item["title"] == "Response body inspection incomplete" for item in findings)


@pytest.mark.parametrize("content_length", [None, "1", "999999999"])
def test_inspect_url_caps_oversized_stream_without_trusting_content_length(
    monkeypatch, content_length
):
    mock_dns(monkeypatch, ["8.8.8.8"])
    target = validate_target("https://scanner.example.test")
    stream = RepeatingStream(
        b"traceback " + b"x" * (STREAM_CHUNK_BYTES - len("traceback ")),
    )
    headers = {}
    if content_length is not None:
        headers["content-length"] = content_length
    original_reader = scanner._read_bounded_response_body
    inspected_byte_lengths = []

    def record_inspected_bytes(response):
        body, incomplete_reason = original_reader(response)
        inspected_byte_lengths.append(len(body.encode("utf-8")))
        return body, incomplete_reason

    def handler(request):
        assert request.headers["accept-encoding"] == "identity"
        return httpx.Response(200, headers=headers, stream=stream, request=request)

    monkeypatch.setattr(scanner, "_tls_finding", lambda _target: [])
    monkeypatch.setattr(scanner, "_read_bounded_response_body", record_inspected_bytes)
    monkeypatch.setattr(
        scanner, "_PinnedHTTPTransport", lambda _target: httpx.MockTransport(handler)
    )

    findings = scanner.inspect_url(target)

    assert stream.chunks_yielded == (
        scanner.MAX_RESPONSE_BODY_BYTES + STREAM_CHUNK_BYTES - 1
    ) // STREAM_CHUNK_BYTES
    assert inspected_byte_lengths == [scanner.MAX_RESPONSE_BODY_BYTES]
    assert stream.closed
    assert any(item["title"] == "Debug or framework information exposed" for item in findings)
    incomplete = next(
        item for item in findings if item["title"] == "Response body inspection incomplete"
    )
    assert "assessment is incomplete" in incomplete["evidence"]


def test_inspect_url_accepts_body_exactly_at_limit(monkeypatch):
    mock_dns(monkeypatch, ["8.8.8.8"])
    target = validate_target("https://scanner.example.test")
    stream = RepeatingStream(b"x" * scanner.MAX_RESPONSE_BODY_BYTES, max_chunks=1)

    def handler(request):
        return httpx.Response(
            200,
            headers={"content-length": str(scanner.MAX_RESPONSE_BODY_BYTES)},
            stream=stream,
            request=request,
        )

    monkeypatch.setattr(scanner, "_tls_finding", lambda _target: [])
    monkeypatch.setattr(
        scanner, "_PinnedHTTPTransport", lambda _target: httpx.MockTransport(handler)
    )

    findings = scanner.inspect_url(target)

    assert stream.closed
    assert not any(item["title"] == "Response body inspection incomplete" for item in findings)


def test_inspect_url_inspects_normal_body_and_closes_response(monkeypatch):
    mock_dns(monkeypatch, ["8.8.8.8"])
    target = validate_target("https://scanner.example.test")
    stream = RepeatingStream(b"traceback from application", max_chunks=1)

    def handler(request):
        return httpx.Response(200, stream=stream, request=request)

    monkeypatch.setattr(scanner, "_tls_finding", lambda _target: [])
    monkeypatch.setattr(
        scanner, "_PinnedHTTPTransport", lambda _target: httpx.MockTransport(handler)
    )

    findings = scanner.inspect_url(target)

    assert stream.closed
    assert any(item["title"] == "Debug or framework information exposed" for item in findings)
    assert not any(item["title"] == "Response body inspection incomplete" for item in findings)


def test_inspect_url_accepts_empty_body_and_closes_response(monkeypatch):
    mock_dns(monkeypatch, ["8.8.8.8"])
    target = validate_target("https://scanner.example.test")
    stream = RepeatingStream(b"", max_chunks=0)

    def handler(request):
        return httpx.Response(200, stream=stream, request=request)

    monkeypatch.setattr(scanner, "_tls_finding", lambda _target: [])
    monkeypatch.setattr(
        scanner, "_PinnedHTTPTransport", lambda _target: httpx.MockTransport(handler)
    )

    findings = scanner.inspect_url(target)

    assert stream.closed
    assert not any(item["title"] == "Response body inspection incomplete" for item in findings)


def test_inspect_url_marks_encoded_body_uninspected(monkeypatch):
    mock_dns(monkeypatch, ["8.8.8.8"])
    target = validate_target("https://scanner.example.test")
    stream = RepeatingStream(b"compressed content", max_chunks=1)

    def handler(request):
        return httpx.Response(
            200,
            headers={"content-encoding": "gzip"},
            stream=stream,
            request=request,
        )

    monkeypatch.setattr(scanner, "_tls_finding", lambda _target: [])
    monkeypatch.setattr(
        scanner, "_PinnedHTTPTransport", lambda _target: httpx.MockTransport(handler)
    )

    findings = scanner.inspect_url(target)

    assert stream.closed
    incomplete = next(
        item for item in findings if item["title"] == "Response body inspection incomplete"
    )
    assert "encoded response body" in incomplete["evidence"]


def test_inspect_url_reports_read_timeout_and_closes_response(monkeypatch):
    mock_dns(monkeypatch, ["8.8.8.8"])
    target = validate_target("https://scanner.example.test")
    stream = FailingStream()

    def handler(request):
        return httpx.Response(200, stream=stream, request=request)

    monkeypatch.setattr(scanner, "_tls_finding", lambda _target: [])
    monkeypatch.setattr(
        scanner, "_PinnedHTTPTransport", lambda _target: httpx.MockTransport(handler)
    )

    findings = scanner.inspect_url(target)

    assert stream.closed
    assert findings[0]["title"] == "Target could not be assessed"


@pytest.mark.parametrize(
    ("category", "title"),
    [
        ("Assessment coverage", "Response body inspection incomplete"),
        ("Availability", "Target could not be assessed"),
    ],
)
def test_execute_scan_marks_incomplete_assessment_in_summary(
    monkeypatch, category, title
):
    from app import database

    updates = []
    monkeypatch.setattr(
        database,
        "one",
        lambda _query, _parameters: {"id": 12, "target_url": "http://scanner.example.test"},
    )
    monkeypatch.setattr(scanner, "validate_target", lambda url: scanner.Target(url, "scanner.example.test", 80, ("8.8.8.8",)))
    monkeypatch.setattr(
        scanner,
        "inspect_url",
        lambda _target: [
            scanner._finding(
                category,
                title,
                "info",
                "Only a bounded portion was inspected.",
                "The assessment is incomplete.",
                "Review the response.",
                "Moderate",
            )
        ],
    )
    monkeypatch.setattr(scanner, "update_scan", lambda _scan_id, **fields: updates.append(fields))
    monkeypatch.setattr(scanner, "insert_findings", lambda _scan_id, _findings: None)

    scanner.execute_scan(12)

    completed = next(update for update in updates if update.get("status") == "completed")
    assert completed["summary"].startswith("Incomplete assessment.")


def test_tls_probe_pins_ip_and_preserves_hostname_verification(monkeypatch):
    mock_dns(monkeypatch, ["8.8.8.8"])
    target = validate_target("https://scanner.example.test:9443")
    raw_socket = MagicMock()
    raw_socket.__enter__.return_value = raw_socket
    secure_socket = MagicMock()
    secure_socket.__enter__.return_value = secure_socket
    secure_socket.getpeercert.return_value = {"subject": ()}
    ssl_context = ssl.create_default_context()
    calls = []

    class TLSContextProbe:
        check_hostname = ssl_context.check_hostname
        verify_mode = ssl_context.verify_mode

        def wrap_socket(self, raw, *, server_hostname):
            calls.append((raw, server_hostname))
            return secure_socket

    connect = Mock(return_value=raw_socket)
    monkeypatch.setattr(scanner.ssl, "create_default_context", lambda: TLSContextProbe())
    monkeypatch.setattr(scanner.socket, "create_connection", connect)

    assert scanner._tls_finding(target) == []
    connect.assert_called_once_with(("8.8.8.8", 9443), timeout=scanner.settings.scan_timeout_seconds)
    assert calls == [(raw_socket, "scanner.example.test")]
    assert TLSContextProbe.check_hostname is True
    assert TLSContextProbe.verify_mode == ssl.CERT_REQUIRED


def test_secret_patterns_regex():
    sample_corpus = "const API_KEY = 'AIzaSyD-1234567890123456789012345678901';"
    matched = False
    for pattern, title in SECRET_PATTERNS:
        if pattern.search(sample_corpus):
            matched = True
            break
    assert matched, "Firebase API key pattern should match sample corpus"


def test_inspect_source_oversized_archive():
    huge_bytes = b"0" * (6 * 1024 * 1024)
    findings = inspect_source(huge_bytes, "huge.zip")
    assert len(findings) == 1
    assert "not inspected" in findings[0]["title"]
