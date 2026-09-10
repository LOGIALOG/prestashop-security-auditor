import json

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from backend.app.manifest_signing import sign_manifest, verify_manifest_signature


def write_keys(tmp_path):
    private = Ed25519PrivateKey.generate()
    private_path = tmp_path / "private.pem"
    public_path = tmp_path / "public.pem"
    private_path.write_bytes(private.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    public_path.write_bytes(private.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    return private_path, public_path


def test_ed25519_manifest_signature_round_trip(tmp_path):
    manifest = tmp_path / "manifest.json"
    signature = tmp_path / "manifest.sig.json"
    manifest.write_text('{"record_count":2}\n', encoding="utf-8")
    private, public = write_keys(tmp_path)
    envelope = sign_manifest(manifest, private)
    signature.write_text(envelope.model_dump_json(), encoding="utf-8")

    verified = verify_manifest_signature(manifest, signature, public)

    assert verified.algorithm == "Ed25519"
    assert len(verified.key_id) == 16


def test_signature_rejects_manifest_tampering(tmp_path):
    manifest = tmp_path / "manifest.json"
    signature = tmp_path / "manifest.sig.json"
    manifest.write_text('{"record_count":2}\n', encoding="utf-8")
    private, public = write_keys(tmp_path)
    signature.write_text(sign_manifest(manifest, private).model_dump_json(), encoding="utf-8")
    manifest.write_text('{"record_count":3}\n', encoding="utf-8")

    with pytest.raises(ValueError, match="hash signé"):
        verify_manifest_signature(manifest, signature, public)


def test_signature_rejects_wrong_public_key(tmp_path):
    manifest = tmp_path / "manifest.json"
    signature = tmp_path / "manifest.sig.json"
    manifest.write_text('{}\n', encoding="utf-8")
    private, _ = write_keys(tmp_path)
    wrong = Ed25519PrivateKey.generate().public_key()
    wrong_path = tmp_path / "wrong-public.pem"
    wrong_path.write_bytes(wrong.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    signature.write_text(sign_manifest(manifest, private).model_dump_json(), encoding="utf-8")
    with pytest.raises(ValueError, match="clé publique"):
        verify_manifest_signature(manifest, signature, wrong_path)
