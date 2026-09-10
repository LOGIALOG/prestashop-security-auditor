import zipfile

import pytest

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
    assert next(item for item in result.differences if item.status == "added").actual_sha256 is None


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
