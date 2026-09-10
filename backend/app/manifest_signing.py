from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from pydantic import BaseModel, ConfigDict


class ManifestSignature(BaseModel):
    model_config = ConfigDict(extra="forbid")

    signature_version: Literal[1] = 1
    algorithm: Literal["Ed25519"] = "Ed25519"
    key_id: str
    manifest_sha256: str
    signature: str


def _public_key_id(key: Ed25519PublicKey) -> str:
    raw = key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return hashlib.sha256(raw).hexdigest()[:16]


def _canonical_manifest_bytes(manifest_path: Path) -> bytes:
    return manifest_path.read_bytes().replace(b"\r\n", b"\n")


def sign_manifest(manifest_path: Path, private_key_path: Path, password: bytes | None = None) -> ManifestSignature:
    return sign_payload(_canonical_manifest_bytes(manifest_path), private_key_path, password)


def sign_payload(payload: bytes, private_key_path: Path, password: bytes | None = None) -> ManifestSignature:
    loaded = serialization.load_pem_private_key(private_key_path.read_bytes(), password=password)
    if not isinstance(loaded, Ed25519PrivateKey):
        raise ValueError("La clé privée doit être une clé Ed25519")
    signature = loaded.sign(payload)
    return ManifestSignature(
        key_id=_public_key_id(loaded.public_key()),
        manifest_sha256=hashlib.sha256(payload).hexdigest(),
        signature=base64.b64encode(signature).decode("ascii"),
    )


def verify_manifest_signature(manifest_path: Path, signature_path: Path, public_key_path: Path) -> ManifestSignature:
    envelope = ManifestSignature.model_validate(json.loads(signature_path.read_text(encoding="utf-8")))
    return verify_payload_signature(_canonical_manifest_bytes(manifest_path), envelope, public_key_path)


def verify_payload_signature(payload: bytes, envelope: ManifestSignature, public_key_path: Path) -> ManifestSignature:
    loaded = serialization.load_pem_public_key(public_key_path.read_bytes())
    if not isinstance(loaded, Ed25519PublicKey):
        raise ValueError("La clé publique doit être une clé Ed25519")
    if envelope.key_id != _public_key_id(loaded):
        raise ValueError("La signature ne correspond pas à la clé publique fournie")
    digest = hashlib.sha256(payload).hexdigest()
    if envelope.manifest_sha256 != digest:
        raise ValueError("Le hash signé ne correspond pas au manifest")
    try:
        loaded.verify(base64.b64decode(envelope.signature, validate=True), payload)
    except (InvalidSignature, ValueError) as exc:
        raise ValueError("Signature Ed25519 invalide") from exc
    return envelope
