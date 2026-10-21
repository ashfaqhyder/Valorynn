import socket
import ssl
from unittest.mock import MagicMock, Mock

import httpcore
import httpx
import pytest

from app import scanner
from app.scanner import SECRET_PATTERNS, inspect_source, validate_target


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
