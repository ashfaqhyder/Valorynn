from app.security import create_session, hash_password, read_session, verify_password


def test_scrypt_password_hash_round_trip() -> None:
    stored = hash_password("long-enough-test-password")
    assert stored.startswith("scrypt$")
    assert verify_password("long-enough-test-password", stored)
    assert not verify_password("wrong-password", stored)


def test_signed_session_rejects_tampering() -> None:
    session = create_session(7)
    assert read_session(session) == 7
    assert read_session(session + "x") is None
