from __future__ import annotations

import base64
import hashlib
import ipaddress
import re
import secrets
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Callable, Mapping
from urllib.parse import urlsplit

from . import database

CHALLENGE_TTL = timedelta(minutes=30)
TOKEN_BYTES = 32

STATUS_PENDING = "PENDING"
STATUS_VERIFIED = "VERIFIED"
STATUS_REVOKED = "REVOKED"
STATUS_EXPIRED = "EXPIRED"
PERSISTED_STATUSES = frozenset({STATUS_PENDING, STATUS_VERIFIED, STATUS_REVOKED})

VERIFICATION_METHODS = frozenset({"dns_txt", "well_known"})

REASON_INVALID_TARGET = "INVALID_TARGET"
REASON_HTTPS_REQUIRED = "HTTPS_REQUIRED"
REASON_UNSUPPORTED_PORT = "UNSUPPORTED_PORT"
REASON_CHALLENGE_NOT_FOUND = "CHALLENGE_NOT_FOUND"
REASON_CHALLENGE_EXPIRED = "CHALLENGE_EXPIRED"
REASON_NOT_AUTHORIZED = "NOT_AUTHORIZED"
REASON_INVALID_VERIFICATION_METHOD = "INVALID_VERIFICATION_METHOD"

_HOSTNAME_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_LABEL_PATTERN = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?$")


class AuthorizationError(ValueError):
    def __init__(self, reason: str, message: str = "") -> None:
        self.reason = reason
        super().__init__(message or reason)


class AuthorizationStateError(RuntimeError):
    pass


@dataclass(frozen=True)
class CanonicalTarget:
    canonical_host: str
    canonical_origin: str


@dataclass(frozen=True)
class ChallengeIssued:
    challenge_id: str
    canonical_origin: str
    canonical_host: str
    created_at: datetime
    expires_at: datetime
    effective_status: str
    token: str = field(repr=False)


@dataclass(frozen=True)
class ChallengeStatusView:
    challenge_id: str
    effective_status: str
    created_at: datetime
    expires_at: datetime
    verification_method: str | None
    verified_at: datetime | None
    initial_scan_consumed: bool
    rescan_consumed: bool


def format_utc(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise AuthorizationStateError("timestamp must be timezone-aware")
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds")


def parse_utc(text: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(text)
    except (TypeError, ValueError) as exc:
        raise AuthorizationStateError("invalid timestamp representation") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise AuthorizationStateError("timestamp must be timezone-aware")
    return parsed.astimezone(timezone.utc)


def _utc_now(now: datetime | None) -> datetime:
    if now is None:
        return datetime.now(timezone.utc)
    if now.tzinfo is None or now.utcoffset() is None:
        raise AuthorizationStateError("now must be timezone-aware")
    return now.astimezone(timezone.utc)


def canonicalize_public_target(target: str) -> CanonicalTarget:
    if not isinstance(target, str):
        raise AuthorizationError(REASON_INVALID_TARGET)
    if not target or any(ord(character) < 0x20 for character in target):
        raise AuthorizationError(REASON_INVALID_TARGET)
    try:
        parts = urlsplit(target)
    except ValueError as exc:
        raise AuthorizationError(REASON_INVALID_TARGET) from exc
    scheme = parts.scheme.lower()
    if not scheme:
        raise AuthorizationError(REASON_INVALID_TARGET)
    if scheme != "https":
        raise AuthorizationError(REASON_HTTPS_REQUIRED)
    if "@" in parts.netloc or parts.username is not None or parts.password is not None:
        raise AuthorizationError(REASON_INVALID_TARGET)
    if parts.netloc.endswith(":"):
        raise AuthorizationError(REASON_INVALID_TARGET)
    if parts.query or parts.fragment:
        raise AuthorizationError(REASON_INVALID_TARGET)
    if parts.path not in ("", "/"):
        raise AuthorizationError(REASON_INVALID_TARGET)
    try:
        port = parts.port
    except ValueError as exc:
        raise AuthorizationError(REASON_INVALID_TARGET) from exc
    if port is not None and port != 443:
        raise AuthorizationError(REASON_UNSUPPORTED_PORT)
    try:
        raw_host = parts.hostname
    except ValueError as exc:
        raise AuthorizationError(REASON_INVALID_TARGET) from exc
    if not raw_host:
        raise AuthorizationError(REASON_INVALID_TARGET)
    if raw_host.endswith("."):
        raw_host = raw_host[:-1]
    if not raw_host or raw_host.endswith("."):
        raise AuthorizationError(REASON_INVALID_TARGET)
    if _is_ip_literal(raw_host):
        raise AuthorizationError(REASON_INVALID_TARGET)
    try:
        ascii_host = raw_host.lower().encode("idna").decode("ascii")
    except (UnicodeError, ValueError) as exc:
        raise AuthorizationError(REASON_INVALID_TARGET) from exc
    _validate_ascii_host(ascii_host)
    if _is_ip_literal(ascii_host) or _is_ipv4_numeric_alias(ascii_host):
        raise AuthorizationError(REASON_INVALID_TARGET)
    return CanonicalTarget(canonical_host=ascii_host, canonical_origin=f"https://{ascii_host}")


def _is_ip_literal(host: str) -> bool:
    candidate = host[1:-1] if host.startswith("[") and host.endswith("]") else host
    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        return False
    return True


def _parse_ipv4_component(component: str) -> int | None:
    if re.fullmatch(r"0[xX][0-9a-fA-F]+", component):
        return int(component, 16)
    if len(component) > 1 and component.startswith("0") and re.fullmatch(r"[0-7]+", component):
        return int(component, 8)
    if re.fullmatch(r"[0-9]+", component):
        return int(component, 10)
    return None


def _is_ipv4_numeric_alias(host: str) -> bool:
    components = host.split(".")
    if not 1 <= len(components) <= 4:
        return False
    values = [_parse_ipv4_component(component) for component in components]
    if any(value is None for value in values):
        return False
    limits = {
        1: [0xFFFFFFFF],
        2: [0xFF, 0xFFFFFF],
        3: [0xFF, 0xFF, 0xFFFF],
        4: [0xFF, 0xFF, 0xFF, 0xFF],
    }[len(values)]
    return all(value <= limit for value, limit in zip(values, limits))


def _validate_ascii_host(host: str) -> None:
    if not host or len(host) > 253:
        raise AuthorizationError(REASON_INVALID_TARGET)
    labels = host.split(".")
    for label in labels:
        if not label or len(label) > 63 or not _LABEL_PATTERN.fullmatch(label):
            raise AuthorizationError(REASON_INVALID_TARGET)


def generate_token(entropy: Callable[[int], bytes] | None = None) -> str:
    raw = (entropy or secrets.token_bytes)(TOKEN_BYTES)
    if not isinstance(raw, (bytes, bytearray)) or len(raw) != TOKEN_BYTES:
        raise AuthorizationStateError("entropy source returned an invalid token")
    return base64.urlsafe_b64encode(bytes(raw)).rstrip(b"=").decode("ascii")


def token_digest(token: str) -> str:
    return hashlib.sha256(token.encode("ascii")).hexdigest()


def effective_status(record: Mapping[str, object], now: datetime) -> str:
    status = record["status"]
    if status == STATUS_REVOKED:
        return STATUS_REVOKED
    if now >= record["expires_at"]:
        return STATUS_EXPIRED
    return str(status)


def _load_record(challenge_id: str) -> dict | None:
    row = database.get_authorization_challenge(challenge_id)
    if row is None:
        return None
    return _validate_record(row)


def _validate_record(row: Mapping[str, object]) -> dict:
    challenge_id = row.get("id")
    if not isinstance(challenge_id, str) or not challenge_id:
        raise AuthorizationStateError("challenge id missing")
    try:
        uuid.UUID(challenge_id)
    except (TypeError, ValueError) as exc:
        raise AuthorizationStateError("challenge id malformed") from exc
    canonical_host = row.get("canonical_host")
    canonical_origin = row.get("canonical_origin")
    if not isinstance(canonical_host, str) or not isinstance(canonical_origin, str):
        raise AuthorizationStateError("canonical identity malformed")
    if canonical_origin != f"https://{canonical_host}":
        raise AuthorizationStateError("canonical origin mismatch")
    digest = row.get("token_sha256")
    if not isinstance(digest, str) or not _HOSTNAME_SHA256_PATTERN.fullmatch(digest):
        raise AuthorizationStateError("token digest malformed")
    status = row.get("status")
    if status not in PERSISTED_STATUSES:
        raise AuthorizationStateError("persisted status malformed")
    created_at = parse_utc(row.get("created_at"))
    expires_at = parse_utc(row.get("expires_at"))
    if expires_at <= created_at:
        raise AuthorizationStateError("expiry precedes creation")
    verified_at_raw = row.get("verified_at")
    verification_method = row.get("verification_method")
    verified_at = parse_utc(verified_at_raw) if verified_at_raw else None
    if status == STATUS_VERIFIED:
        if verified_at is None or verification_method not in VERIFICATION_METHODS:
            raise AuthorizationStateError("verified challenge missing verification metadata")
    if status == STATUS_PENDING and (verified_at is not None or verification_method is not None):
        raise AuthorizationStateError("pending challenge carries verification metadata")
    if verification_method is not None and verification_method not in VERIFICATION_METHODS:
        raise AuthorizationStateError("verification method malformed")
    initial_raw = row.get("initial_scan_consumed_at")
    rescan_raw = row.get("rescan_consumed_at")
    return {
        "id": challenge_id,
        "canonical_origin": canonical_origin,
        "canonical_host": canonical_host,
        "token_sha256": digest,
        "status": status,
        "created_at": created_at,
        "expires_at": expires_at,
        "verified_at": verified_at,
        "verification_method": verification_method,
        "initial_scan_consumed_at": parse_utc(initial_raw) if initial_raw else None,
        "rescan_consumed_at": parse_utc(rescan_raw) if rescan_raw else None,
    }


def create_challenge(
    target: str,
    *,
    now: datetime | None = None,
    entropy: Callable[[int], bytes] | None = None,
    challenge_id: str | None = None,
) -> ChallengeIssued:
    canonical = canonicalize_public_target(target)
    created = _utc_now(now)
    expires = created + CHALLENGE_TTL
    identifier = challenge_id or str(uuid.uuid4())
    try:
        uuid.UUID(identifier)
    except (TypeError, ValueError) as exc:
        raise AuthorizationStateError("challenge id malformed") from exc
    token = generate_token(entropy)
    database.insert_authorization_challenge(
        identifier,
        canonical.canonical_origin,
        canonical.canonical_host,
        token_digest(token),
        format_utc(created),
        format_utc(expires),
    )
    return ChallengeIssued(
        challenge_id=identifier,
        canonical_origin=canonical.canonical_origin,
        canonical_host=canonical.canonical_host,
        created_at=created,
        expires_at=expires,
        effective_status=STATUS_PENDING,
        token=token,
    )


def get_challenge_status(challenge_id: str, *, now: datetime | None = None) -> ChallengeStatusView:
    record = _load_record(challenge_id)
    if record is None:
        raise AuthorizationError(REASON_CHALLENGE_NOT_FOUND)
    current = _utc_now(now)
    return _status_view(record, current)


def _status_view(record: Mapping[str, object], now: datetime) -> ChallengeStatusView:
    return ChallengeStatusView(
        challenge_id=str(record["id"]),
        effective_status=effective_status(record, now),
        created_at=record["created_at"],
        expires_at=record["expires_at"],
        verification_method=record["verification_method"],
        verified_at=record["verified_at"],
        initial_scan_consumed=record["initial_scan_consumed_at"] is not None,
        rescan_consumed=record["rescan_consumed_at"] is not None,
    )


def mark_challenge_verified(
    challenge_id: str,
    verification_method: str,
    *,
    now: datetime | None = None,
) -> ChallengeStatusView:
    if verification_method not in VERIFICATION_METHODS:
        raise AuthorizationError(REASON_INVALID_VERIFICATION_METHOD)
    current = _utc_now(now)
    rowcount = database.mark_challenge_verified(
        challenge_id,
        verification_method,
        format_utc(current),
        format_utc(current),
    )
    if rowcount == 1:
        record = _load_record(challenge_id)
        if record is None:
            raise AuthorizationStateError("challenge vanished after verification transition")
        return _status_view(record, current)
    record = _load_record(challenge_id)
    if record is None:
        raise AuthorizationError(REASON_CHALLENGE_NOT_FOUND)
    status = effective_status(record, current)
    if status == STATUS_REVOKED:
        raise AuthorizationError(REASON_NOT_AUTHORIZED)
    if status == STATUS_EXPIRED:
        raise AuthorizationError(REASON_CHALLENGE_EXPIRED)
    if status == STATUS_VERIFIED:
        return _status_view(record, current)
    raise AuthorizationError(REASON_NOT_AUTHORIZED)


def revoke_challenge(challenge_id: str, *, now: datetime | None = None) -> ChallengeStatusView:
    current = _utc_now(now)
    rowcount = database.revoke_authorization_challenge(challenge_id)
    if rowcount == 0:
        record = _load_record(challenge_id)
        if record is None:
            raise AuthorizationError(REASON_CHALLENGE_NOT_FOUND)
        if record["status"] != STATUS_REVOKED:
            raise AuthorizationError(REASON_NOT_AUTHORIZED)
    record = _load_record(challenge_id)
    if record is None:
        raise AuthorizationError(REASON_CHALLENGE_NOT_FOUND)
    return _status_view(record, current)


def purge_expired_challenges(now: datetime | None = None) -> int:
    current = _utc_now(now)
    return database.purge_expired_challenges(format_utc(current))
