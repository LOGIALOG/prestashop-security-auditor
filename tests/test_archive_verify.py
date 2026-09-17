import hashlib
import os
import zipfile
from pathlib import Path

import pytest

from backend.app import archive_verify
from backend.app.archive_verify import compare_with_zip


def make_zip(path, files):
    with zipfile.ZipFile(path, "w") as archive:
        for name, content in files.items():
            archive.writestr(name, content)


def test_archive_comparison_reports_modified_and_missing_files(tmp_path):
    source = tmp_path / "shop"
    source.mkdir()
    (source / "same.php").write_text("same", encoding="utf-8")
    (source / "changed.php").write_text("local", encoding="utf-8")
    (source / "custom.php").write_text("custom", encoding="utf-8")
    cache = source / "var" / "cache"
    cache.mkdir(parents=True)
    (cache / "ignored.php").write_text("generated", encoding="utf-8")
    reference = tmp_path / "official.zip"
    make_zip(reference, {"prestashop/same.php": "same", "prestashop/changed.php": "official", "prestashop/missing.php": "official"})

    result = compare_with_zip(source, reference)

    assert result.checked_files == 3
    assert [(item.path, item.status) for item in result.differences] == [("changed.php", "modified"), ("custom.php", "added"), ("missing.php", "missing")]
    assert all(item.expected_sha256 for item in result.differences if item.status != "added")
    added = next(item for item in result.differences if item.status == "added")
    assert added.expected_sha256 is None
    assert added.actual_sha256 == hashlib.sha256(b"custom").hexdigest()


def test_archive_comparison_hashes_multiple_added_files_independently(tmp_path):
    source = tmp_path / "shop"
    source.mkdir()
    (source / "first.php").write_text("first-content", encoding="utf-8")
    (source / "second.php").write_text("second-content", encoding="utf-8")
    reference = tmp_path / "official.zip"
    make_zip(reference, {"prestashop/present.php": "present"})

    result = compare_with_zip(source, reference)

    added = {item.path: item for item in result.differences if item.status == "added"}
    assert set(added) == {"first.php", "second.php"}
    assert added["first.php"].actual_sha256 == hashlib.sha256(b"first-content").hexdigest()
    assert added["second.php"].actual_sha256 == hashlib.sha256(b"second-content").hexdigest()
    assert added["first.php"].actual_sha256 != added["second.php"].actual_sha256
    assert all(item.expected_sha256 is None for item in added.values())


def test_archive_comparison_hashes_binary_added_file_as_raw_bytes(tmp_path):
    source = tmp_path / "shop"
    source.mkdir()
    payload = bytes([0x00, 0x01, 0x02, 0xFF, 0xFE, 0x0A, 0x0D])
    (source / "asset.ts").write_bytes(payload)
    reference = tmp_path / "official.zip"
    make_zip(reference, {})

    result = compare_with_zip(source, reference)

    added = next(item for item in result.differences if item.status == "added")
    assert added.path == "asset.ts"
    assert added.actual_sha256 == hashlib.sha256(payload).hexdigest()


def test_archive_comparison_rejects_oversized_added_file(tmp_path, monkeypatch):
    source = tmp_path / "shop"
    source.mkdir()
    (source / "big.php").write_text("0123456789", encoding="utf-8")
    reference = tmp_path / "official.zip"
    make_zip(reference, {})
    monkeypatch.setattr(archive_verify, "MAX_SINGLE_FILE_BYTES", 4)

    with pytest.raises(ValueError, match="trop volumineux"):
        compare_with_zip(source, reference)


def test_archive_comparison_rejects_cumulative_added_bytes(tmp_path, monkeypatch):
    source = tmp_path / "shop"
    source.mkdir()
    (source / "a.php").write_text("aaaa", encoding="utf-8")
    (source / "b.php").write_text("bbbb", encoding="utf-8")
    reference = tmp_path / "official.zip"
    make_zip(reference, {})
    monkeypatch.setattr(archive_verify, "MAX_UNCOMPRESSED_BYTES", 5)

    hashed = []
    real_stream = archive_verify._sha256_stream

    def recording_stream(stream):
        hashed.append(1)
        return real_stream(stream)

    monkeypatch.setattr(archive_verify, "_sha256_stream", recording_stream)

    with pytest.raises(ValueError, match="cumul"):
        compare_with_zip(source, reference)

    assert len(hashed) == 1, "the budget-crossing candidate must not be hashed"


def test_archive_comparison_added_open_failure_fails_closed(tmp_path, monkeypatch):
    source = tmp_path / "shop"
    source.mkdir()
    (source / "custom.php").write_text("custom", encoding="utf-8")
    reference = tmp_path / "official.zip"
    make_zip(reference, {})

    real_open = Path.open

    def flaky_open(self, *args, **kwargs):
        if self.name == "custom.php":
            raise OSError("synthetic read failure")
        return real_open(self, *args, **kwargs)

    monkeypatch.setattr(Path, "open", flaky_open)

    with pytest.raises(ValueError, match="Lecture impossible"):
        compare_with_zip(source, reference)


def test_archive_comparison_does_not_follow_added_symlink(tmp_path):
    source = tmp_path / "shop"
    source.mkdir()
    target = source / "real.php"
    target.write_text("target", encoding="utf-8")
    link = source / "linked.php"
    try:
        os.symlink(target, link)
    except (OSError, NotImplementedError):
        pytest.skip("platform cannot create symlinks")

    reference = tmp_path / "official.zip"
    make_zip(reference, {})

    result = compare_with_zip(source, reference)

    added_paths = {item.path for item in result.differences if item.status == "added"}
    assert "linked.php" not in added_paths
    assert "real.php" in added_paths


def test_archive_comparison_rejects_path_traversal(tmp_path):
    source = tmp_path / "shop"
    source.mkdir()
    reference = tmp_path / "unsafe.zip"
    make_zip(reference, {"../outside.php": "unsafe"})

    with pytest.raises(ValueError, match="Chemin dangereux"):
        compare_with_zip(source, reference)


def test_archive_comparison_never_executes_php(tmp_path):
    source = tmp_path / "shop"
    source.mkdir()
    marker = tmp_path / "executed.txt"
    (source / "module.php").write_text(f"<?php file_put_contents('{marker}', 'bad');", encoding="utf-8")
    reference = tmp_path / "official.zip"
    make_zip(reference, {"module.php": "<?php return true;"})

    result = compare_with_zip(source, reference)

    assert result.source_code_executed is False
    assert not marker.exists()


def test_archive_comparison_format_and_hash_semantics_regression(tmp_path):
    source = tmp_path / "shop"
    source.mkdir()
    (source / "changed.php").write_text("local", encoding="utf-8")
    (source / "added.php").write_text("added", encoding="utf-8")
    reference = tmp_path / "official.zip"
    make_zip(reference, {"changed.php": "official", "missing.php": "official"})

    result = compare_with_zip(source, reference)

    assert result.format == "logialog-archive-comparison"
    assert result.format_version == "1.0"
    assert result.network_access is False
    assert result.source_code_executed is False
    assert result.checked_files == 2
    modified = next(item for item in result.differences if item.status == "modified")
    missing = next(item for item in result.differences if item.status == "missing")
    assert modified.expected_sha256 == hashlib.sha256(b"official").hexdigest()
    assert modified.actual_sha256 == hashlib.sha256(b"local").hexdigest()
    assert missing.expected_sha256 == hashlib.sha256(b"official").hexdigest()
    assert missing.actual_sha256 is None
