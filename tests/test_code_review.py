from backend.app.code_review import review_local_php


def test_code_review_returns_file_line_without_source_content(tmp_path):
    module = tmp_path / "modules" / "sample"
    module.mkdir(parents=True)
    (module / "sample.php").write_text("<?php\n$value = base64_decode($input);\neval($value);", encoding="utf-8")
    result = review_local_php(tmp_path)
    assert [(item.rule_id, item.line, item.confidence) for item in result.signals] == [("PHP-BASE64-DECODE", 2, "low"), ("PHP-EVAL", 3, "high")]
    assert result.source_content_exported is False
    assert "$input" not in result.model_dump_json()


def test_code_review_flags_request_controlled_unserialize(tmp_path):
    (tmp_path / "controller.php").write_text("<?php\n$data = unserialize(Tools::getValue('payload'));", encoding="utf-8")
    result = review_local_php(tmp_path)
    assert result.signals[0].rule_id == "PHP-UNSERIALIZE-INPUT"
    assert result.signals[0].line == 2


def test_code_review_skips_vendor_and_symlinks(tmp_path):
    vendor = tmp_path / "vendor" / "package"
    vendor.mkdir(parents=True)
    (vendor / "ignored.php").write_text("<?php eval($x);", encoding="utf-8")
    outside = tmp_path.parent / "outside-review.php"
    outside.write_text("<?php eval($x);", encoding="utf-8")
    try:
        (tmp_path / "linked.php").symlink_to(outside)
    except OSError:
        pass
    assert review_local_php(tmp_path).signals == []


import hashlib
import io
import json
from pathlib import Path

import pytest

from backend.app import code_review
from backend.app.code_review import CodeReviewSignal, review_local_php


def write_php(directory, name, content: bytes):
    target = directory / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(content)
    return target


def test_signal_carries_valid_file_sha256(tmp_path):
    raw = b"<?php\neval($value);"
    write_php(tmp_path, "sample.php", raw)

    result = review_local_php(tmp_path)

    signal = next(item for item in result.signals if item.rule_id == "PHP-EVAL")
    assert signal.file_sha256 == hashlib.sha256(raw).hexdigest()
    assert len(signal.file_sha256) == 64
    assert all(character in "0123456789abcdef" for character in signal.file_sha256)


def test_multiple_signals_share_the_same_file_sha256(tmp_path):
    write_php(tmp_path, "multi.php", b"<?php\n$v = base64_decode($in);\neval($v);\nshell_exec($cmd);")

    result = review_local_php(tmp_path)

    digests = {signal.file_sha256 for signal in result.signals}
    assert len(result.signals) == 3
    assert len(digests) == 1
    expected = hashlib.sha256((tmp_path / "multi.php").read_bytes()).hexdigest()
    assert digests == {expected}


def test_one_byte_change_changes_file_sha256(tmp_path):
    write_php(tmp_path, "a.php", b"<?php\neval($x);")
    first = review_local_php(tmp_path).signals[0].file_sha256

    write_php(tmp_path, "a.php", b"<?php\neval($y);")
    second = review_local_php(tmp_path).signals[0].file_sha256

    assert first != second


def test_identical_bytes_produce_identical_digest(tmp_path):
    raw = b"<?php\neval($x);"
    write_php(tmp_path, "one.php", raw)
    first = review_local_php(tmp_path).signals[0].file_sha256

    second = review_local_php(tmp_path).signals[0].file_sha256

    assert first == second == hashlib.sha256(raw).hexdigest()


def test_invalid_utf8_still_scans_and_hashes_raw_bytes(tmp_path):
    raw = b"<?php\n\xff\xfe eval($x);"
    write_php(tmp_path, "broken.php", raw)

    result = review_local_php(tmp_path)

    signal = next(item for item in result.signals if item.rule_id == "PHP-EVAL")
    assert signal.line == 2
    assert signal.file_sha256 == hashlib.sha256(raw).hexdigest()


def test_serialized_output_has_no_source_content_or_absolute_path(tmp_path):
    write_php(tmp_path, "secret.php", b"<?php\n$password = 'SUPER_SECRET_SOURCE_VALUE';\neval($password);")

    payload = review_local_php(tmp_path).model_dump_json()

    assert "SUPER_SECRET_SOURCE_VALUE" not in payload
    assert str(tmp_path) not in payload


def test_symlinked_php_file_is_skipped(tmp_path):
    outside = tmp_path.parent / "outside-r6.php"
    outside.write_bytes(b"<?php eval($x);")
    link = tmp_path / "linked.php"
    try:
        link.symlink_to(outside)
    except OSError:
        pytest.skip("platform cannot create symlinks")

    result = review_local_php(tmp_path)

    assert result.signals == []
    assert all(signal.file_sha256 is None for signal in result.signals)


def test_vendor_php_files_are_skipped(tmp_path):
    write_php(tmp_path, "vendor/pkg/ignored.php", b"<?php eval($x);")

    assert review_local_php(tmp_path).signals == []


def test_oversized_file_is_warned_without_signal_or_hash(tmp_path, monkeypatch):
    monkeypatch.setattr(code_review, "MAX_FILE_BYTES", 4)
    write_php(tmp_path, "big.php", b"<?php eval($x);")

    result = review_local_php(tmp_path)

    assert any("trop volumineux" in warning for warning in result.warnings)
    assert result.signals == []


def test_post_read_bounded_guard_catches_growth_after_stat(tmp_path, monkeypatch):
    monkeypatch.setattr(code_review, "MAX_FILE_BYTES", 4)
    write_php(tmp_path, "grow.php", b"x")

    real_open = Path.open

    def fake_open(self, *args, **kwargs):
        if self.name == "grow.php":
            return io.BytesIO(b"A" * (code_review.MAX_FILE_BYTES + 1))
        return real_open(self, *args, **kwargs)

    monkeypatch.setattr(Path, "open", fake_open)

    result = review_local_php(tmp_path)

    assert any("trop volumineux" in warning for warning in result.warnings)
    assert result.signals == []


def test_legacy_signal_without_hash_deserializes():
    signal = CodeReviewSignal.model_validate(
        {"rule_id": "PHP-EVAL", "relative_path": "a.php", "line": 1, "confidence": "high", "interpretation": "i", "remediation": "r"}
    )

    assert signal.file_sha256 is None


def test_every_generated_signal_has_a_digest(tmp_path):
    write_php(tmp_path, "x.php", b"<?php\neval($a);\nbase64_decode($b);\nshell_exec($c);")

    result = review_local_php(tmp_path)

    assert result.signals
    assert all(signal.file_sha256 and len(signal.file_sha256) == 64 for signal in result.signals)
    assert result.format_version == "1.0"
    assert result.source_content_exported is False
    assert result.source_code_executed is False
    assert result.network_access is False
