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
