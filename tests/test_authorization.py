import base64
import hashlib
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone

import pytest

from backend.app import authorization as auth
from backend.app import database


BASE_TIME = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)


@pytest.fixture
def isolated_db(tmp_path, monkeypatch):
    db_path = tmp_path / "audits.sqlite3"
    monkeypatch.setattr("backend.app.database.DB_PATH", db_path)
    return db_path


def fixed_entropy(size: int) -> bytes:
    return bytes(range(size))


def expected_token() -> str:
    return base64.urlsafe_b64encode(bytes(range(auth.TOKEN_BYTES))).rstrip(b"=").decode("ascii")


def raw_challenge_rows(db_path):
    with sqlite3.connect(db_path) as db:
        return db.execute(f"SELECT {', '.join(database.AUTHORIZATION_CHALLENGE_COLUMNS)} FROM authorization_challenges").fetchall()


def insert_raw(db_path, **values):
    columns = dict(
        id=str(uuid.uuid4()),
        canonical_origin="https://example.com",
        canonical_host="example.com",
        token_sha256="a" * 64,
        status="PENDING",
        created_at=auth.format_utc(BASE_TIME),
        expires_at=auth.format_utc(BASE_TIME + auth.CHALLENGE_TTL),
        verified_at=None,
        verification_method=None,
        initial_scan_consumed_at=None,
        rescan_consumed_at=None,
    )
    columns.update(values)
    with sqlite3.connect(db_path) as db:
        db.execute(
            "INSERT INTO authorization_challenges "
            "(id, canonical_origin, canonical_host, token_sha256, status, created_at, expires_at, "
            "verified_at, verification_method, initial_scan_consumed_at, rescan_consumed_at) "
            "VALUES (:id, :canonical_origin, :canonical_host, :token_sha256, :status, :created_at, "
            ":expires_at, :verified_at, :verification_method, :initial_scan_consumed_at, :rescan_consumed_at)",
            columns,
        )
    return columns["id"]


@pytest.mark.parametrize(
    "target,expected_host",
    [
        ("https://example.com", "example.com"),
        ("https://example.com/", "example.com"),
        ("https://example.com:443", "example.com"),
        ("https://EXAMPLE.com", "example.com"),
        ("https://example.com.", "example.com"),
        ("https://faß.de", "fass.de"),
        ("https://münchen.de", "xn--mnchen-3ya.de"),
    ],
)
def test_canonicalization_accepts(target, expected_host):
    canonical = auth.canonicalize_public_target(target)
    assert canonical.canonical_host == expected_host
    assert canonical.canonical_origin == f"https://{expected_host}"


@pytest.mark.parametrize(
    "target,reason",
    [
        ("http://example.com", auth.REASON_HTTPS_REQUIRED),
        ("https://example.com:8443", auth.REASON_UNSUPPORTED_PORT),
        ("https://user@example.com", auth.REASON_INVALID_TARGET),
        ("https://user:pass@example.com", auth.REASON_INVALID_TARGET),
        ("https://example.com/shop", auth.REASON_INVALID_TARGET),
        ("https://example.com?a=1", auth.REASON_INVALID_TARGET),
        ("https://example.com#frag", auth.REASON_INVALID_TARGET),
        ("https://example.com..", auth.REASON_INVALID_TARGET),
        ("https://.", auth.REASON_INVALID_TARGET),
        ("https://", auth.REASON_INVALID_TARGET),
        ("https://example.com:abc", auth.REASON_INVALID_TARGET),
        ("https://example.com:", auth.REASON_INVALID_TARGET),
        ("https://127.0.0.1", auth.REASON_INVALID_TARGET),
        ("https://8.8.8.8", auth.REASON_INVALID_TARGET),
        ("https://[::1]", auth.REASON_INVALID_TARGET),
        ("https://[2606:4700:4700::1111]", auth.REASON_INVALID_TARGET),
        ("https://-bad.example.com", auth.REASON_INVALID_TARGET),
        ("https://bad-.example.com", auth.REASON_INVALID_TARGET),
        ("https://a_b.example.com", auth.REASON_INVALID_TARGET),
        ("https://exa mple.com", auth.REASON_INVALID_TARGET),
        ("https://" + "a" * 64 + ".example.com", auth.REASON_INVALID_TARGET),
        ("not a url", auth.REASON_INVALID_TARGET),
    ],
)
def test_canonicalization_rejects(target, reason):
    with pytest.raises(auth.AuthorizationError) as excinfo:
        auth.canonicalize_public_target(target)
    assert excinfo.value.reason == reason


def test_canonicalization_rejects_overlong_hostname():
    host = ".".join(["a" * 63] * 5)
    assert len(host) > 253
    with pytest.raises(auth.AuthorizationError):
        auth.canonicalize_public_target(f"https://{host}")


@pytest.mark.parametrize(
    "target",
    [
        "https://2130706433",
        "https://0x7f000001",
        "https://017700000001",
        "https://0177.0.0.1",
        "https://127.1",
        "https://127.0.1",
        "https://0x7f.1",
        "https://0x7f.0.0.1",
        "https://１２７.０.０.１",
        "https://127.0.0.1",
        "https://8.8.8.8",
        "https://[::1]",
        "https://[2606:4700:4700::1111]",
    ],
)
def test_ip_literal_and_numeric_alias_rejected(target):
    with pytest.raises(auth.AuthorizationError) as excinfo:
        auth.canonicalize_public_target(target)
    assert excinfo.value.reason == auth.REASON_INVALID_TARGET


@pytest.mark.parametrize(
    "target,expected_host",
    [
        ("https://example.com", "example.com"),
        ("https://example123.com", "example123.com"),
        ("https://123abc.example", "123abc.example"),
        ("https://shop127.example", "shop127.example"),
        ("https://999999999999999999.example", "999999999999999999.example"),
    ],
)
def test_numeric_looking_dns_names_remain_accepted(target, expected_host):
    canonical = auth.canonicalize_public_target(target)
    assert canonical.canonical_host == expected_host


def test_www_apex_and_subdomains_are_distinct():
    apex = auth.canonicalize_public_target("https://example.com").canonical_origin
    www = auth.canonicalize_public_target("https://www.example.com").canonical_origin
    a = auth.canonicalize_public_target("https://a.example.com").canonical_origin
    b = auth.canonicalize_public_target("https://b.example.com").canonical_origin
    assert len({apex, www, a, b}) == 4


def test_token_shape_and_digest():
    token = auth.generate_token(fixed_entropy)
    assert token == expected_token()
    assert len(token) == 43
    assert set(token) <= set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
    assert "=" not in token
    assert auth.token_digest(token) == hashlib.sha256(token.encode("ascii")).hexdigest()


def test_token_rejects_invalid_entropy():
    with pytest.raises(auth.AuthorizationStateError):
        auth.generate_token(lambda size: b"short")


def test_different_tokens_differ_in_digest():
    first = auth.generate_token(fixed_entropy)
    second = auth.generate_token(lambda size: bytes(range(1, size + 1)))
    assert auth.token_digest(first) != auth.token_digest(second)


def test_create_challenge_persists_only_digest_and_hides_token(isolated_db):
    issued = auth.create_challenge("https://example.com", now=BASE_TIME, entropy=fixed_entropy)

    assert issued.effective_status == auth.STATUS_PENDING
    assert issued.created_at == BASE_TIME
    assert issued.expires_at == BASE_TIME + timedelta(minutes=30)
    assert issued.token == expected_token()
    assert issued.token not in repr(issued)

    rows = raw_challenge_rows(isolated_db)
    assert len(rows) == 1
    row = dict(zip(database.AUTHORIZATION_CHALLENGE_COLUMNS, rows[0]))
    assert row["token_sha256"] == auth.token_digest(issued.token)
    assert row["status"] == "PENDING"
    assert all(issued.token not in str(value) for value in row.values())

    view = auth.get_challenge_status(issued.challenge_id, now=BASE_TIME)
    assert not hasattr(view, "token")
    assert issued.token not in repr(view)
    assert not hasattr(view, "token_sha256")


def test_get_status_missing_challenge(isolated_db):
    with pytest.raises(auth.AuthorizationError) as excinfo:
        auth.get_challenge_status(str(uuid.uuid4()))
    assert excinfo.value.reason == auth.REASON_CHALLENGE_NOT_FOUND


def test_schema_migration_version_and_tables(isolated_db):
    database.init_db()
    with sqlite3.connect(isolated_db) as db:
        version = db.execute("PRAGMA user_version").fetchone()[0]
        tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type = 'table'").fetchall()}
        indexes = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type = 'index'").fetchall()}
    assert version == 4
    assert {"audits", "audit_events", "authorization_challenges"} <= tables
    assert {"idx_authorization_challenges_host", "idx_authorization_challenges_expires"} <= indexes


def test_expired_is_derived_and_does_not_mutate_status(isolated_db):
    issued = auth.create_challenge("https://example.com", now=BASE_TIME, entropy=fixed_entropy)
    view = auth.get_challenge_status(issued.challenge_id, now=BASE_TIME + timedelta(minutes=30))
    assert view.effective_status == auth.STATUS_EXPIRED
    rows = raw_challenge_rows(isolated_db)
    assert dict(zip(database.AUTHORIZATION_CHALLENGE_COLUMNS, rows[0]))["status"] == "PENDING"


def test_ttl_boundary_and_revoked_precedence(isolated_db):
    issued = auth.create_challenge("https://example.com", now=BASE_TIME, entropy=fixed_entropy)
    just_before = auth.get_challenge_status(issued.challenge_id, now=BASE_TIME + timedelta(minutes=30) - timedelta(microseconds=1))
    assert just_before.effective_status == auth.STATUS_PENDING

    auth.revoke_challenge(issued.challenge_id, now=BASE_TIME + timedelta(minutes=31))
    revoked = auth.get_challenge_status(issued.challenge_id, now=BASE_TIME + timedelta(minutes=31))
    assert revoked.effective_status == auth.STATUS_REVOKED


def test_timestamp_format_lexical_ordering():
    first = auth.format_utc(datetime(2026, 1, 1, 12, 0, 0, 1, tzinfo=timezone.utc))
    second = auth.format_utc(datetime(2026, 1, 1, 12, 0, 0, 2, tzinfo=timezone.utc))
    next_second = auth.format_utc(datetime(2026, 1, 1, 12, 0, 1, tzinfo=timezone.utc))
    next_minute = auth.format_utc(datetime(2026, 1, 1, 12, 1, 0, tzinfo=timezone.utc))
    assert first.endswith("+00:00") and first < second < next_second < next_minute
    assert auth.parse_utc(first) < auth.parse_utc(second)
    with pytest.raises(auth.AuthorizationStateError):
        auth.format_utc(datetime(2026, 1, 1, 12, 0, 0))
    with pytest.raises(auth.AuthorizationStateError):
        auth.parse_utc("2026-01-01T12:00:00")


def test_verification_transition_and_idempotency(isolated_db):
    issued = auth.create_challenge("https://example.com", now=BASE_TIME, entropy=fixed_entropy)
    verified = auth.mark_challenge_verified(issued.challenge_id, "dns_txt", now=BASE_TIME + timedelta(seconds=1))
    assert verified.effective_status == auth.STATUS_VERIFIED
    assert verified.verification_method == "dns_txt"
    assert verified.verified_at == BASE_TIME + timedelta(seconds=1)

    repeated = auth.mark_challenge_verified(issued.challenge_id, "well_known", now=BASE_TIME + timedelta(seconds=2))
    assert repeated.effective_status == auth.STATUS_VERIFIED
    assert repeated.verification_method == "dns_txt"
    assert repeated.verified_at == BASE_TIME + timedelta(seconds=1)


def test_verification_rejects_bad_method(isolated_db):
    issued = auth.create_challenge("https://example.com", now=BASE_TIME, entropy=fixed_entropy)
    with pytest.raises(auth.AuthorizationError) as excinfo:
        auth.mark_challenge_verified(issued.challenge_id, "totally-not-a-method", now=BASE_TIME)
    assert excinfo.value.reason == auth.REASON_INVALID_VERIFICATION_METHOD


def test_expired_pending_cannot_verify(isolated_db):
    issued = auth.create_challenge("https://example.com", now=BASE_TIME, entropy=fixed_entropy)
    with pytest.raises(auth.AuthorizationError) as excinfo:
        auth.mark_challenge_verified(issued.challenge_id, "dns_txt", now=BASE_TIME + timedelta(minutes=30))
    assert excinfo.value.reason == auth.REASON_CHALLENGE_EXPIRED


def test_missing_challenge_cannot_verify(isolated_db):
    with pytest.raises(auth.AuthorizationError) as excinfo:
        auth.mark_challenge_verified(str(uuid.uuid4()), "dns_txt", now=BASE_TIME)
    assert excinfo.value.reason == auth.REASON_CHALLENGE_NOT_FOUND


def test_revoked_cannot_verify(isolated_db):
    issued = auth.create_challenge("https://example.com", now=BASE_TIME, entropy=fixed_entropy)
    auth.revoke_challenge(issued.challenge_id, now=BASE_TIME)
    with pytest.raises(auth.AuthorizationError) as excinfo:
        auth.mark_challenge_verified(issued.challenge_id, "dns_txt", now=BASE_TIME)
    assert excinfo.value.reason == auth.REASON_NOT_AUTHORIZED


def test_revocation_idempotent_and_preserves_metadata(isolated_db):
    issued = auth.create_challenge("https://example.com", now=BASE_TIME, entropy=fixed_entropy)
    auth.mark_challenge_verified(issued.challenge_id, "dns_txt", now=BASE_TIME)
    first = auth.revoke_challenge(issued.challenge_id, now=BASE_TIME + timedelta(seconds=1))
    second = auth.revoke_challenge(issued.challenge_id, now=BASE_TIME + timedelta(seconds=2))
    assert first.effective_status == "REVOKED"
    assert second.effective_status == "REVOKED"
    assert second.verification_method == "dns_txt"


def test_purge_boundary_inclusive_and_audit_untouched(isolated_db):
    issued = auth.create_challenge("https://example.com", now=BASE_TIME, entropy=fixed_entropy)
    assert auth.purge_expired_challenges(BASE_TIME + timedelta(minutes=29)) == 0
    assert auth.purge_expired_challenges(BASE_TIME + timedelta(minutes=30)) == 1
    assert raw_challenge_rows(isolated_db) == []
    with sqlite3.connect(isolated_db) as db:
        assert db.execute("SELECT name FROM sqlite_master WHERE name IN ('audits','audit_events')").fetchall()


@pytest.mark.parametrize(
    "overrides",
    [
        {"canonical_origin": "https://evil.test"},
        {"token_sha256": "not-a-digest"},
        {"created_at": "2026-01-01T12:00:00"},
    ],
)
def test_corrupt_rows_fail_closed(isolated_db, overrides):
    database.init_db()
    challenge_id = insert_raw(isolated_db, **overrides)
    with pytest.raises(auth.AuthorizationStateError):
        auth.get_challenge_status(challenge_id, now=BASE_TIME)


def test_schema_check_rejects_unpermitted_status(isolated_db):
    database.init_db()
    with pytest.raises(sqlite3.IntegrityError):
        insert_raw(isolated_db, status="EXPIRED")


def test_verified_row_requires_metadata(isolated_db):
    database.init_db()
    challenge_id = insert_raw(isolated_db, status="VERIFIED")
    with pytest.raises(auth.AuthorizationStateError):
        auth.get_challenge_status(challenge_id, now=BASE_TIME)


def test_pending_row_rejects_verification_metadata(isolated_db):
    database.init_db()
    challenge_id = insert_raw(
        isolated_db,
        status="PENDING",
        verified_at=auth.format_utc(BASE_TIME),
        verification_method="dns_txt",
    )
    with pytest.raises(auth.AuthorizationStateError):
        auth.get_challenge_status(challenge_id, now=BASE_TIME)


def test_created_challenge_has_no_consumption(isolated_db):
    issued = auth.create_challenge("https://example.com", now=BASE_TIME, entropy=fixed_entropy)
    view = auth.get_challenge_status(issued.challenge_id, now=BASE_TIME)
    assert view.initial_scan_consumed is False
    assert view.rescan_consumed is False
