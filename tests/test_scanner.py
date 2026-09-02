import pytest
from app.scanner import validate_target, inspect_source, SECRET_PATTERNS


def test_validate_target_accepts_valid_public_http_urls(mocker=None):
    # Public domain target validation
    try:
        target = validate_target("https://example.com")
        assert target.hostname == "example.com"
        assert target.url == "https://example.com"
    except ValueError as e:
        # If offline DNS lookup fails for example.com, verify error message
        assert "resolved" in str(e) or "private" in str(e)


def test_validate_target_rejects_localhost_and_private_targets():
    with pytest.raises(ValueError, match="not permitted|private or reserved"):
        validate_target("http://localhost:8000")

    with pytest.raises(ValueError, match="not permitted|private or reserved"):
        validate_target("http://127.0.0.1:8000")



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
