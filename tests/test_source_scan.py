import json

from backend.app.source_scan import render_cyclonedx, scan_local_source
from backend.app.version import VERSION


def test_local_source_inventory_and_cyclonedx(tmp_path):
    config = tmp_path / "config"
    module = tmp_path / "modules" / "samplemodule"
    config.mkdir()
    module.mkdir(parents=True)
    (config / "settings.inc.php").write_text("<?php define('_PS_VERSION_', '8.2.8');", encoding="utf-8")
    (module / "config.xml").write_text("<module><version><![CDATA[1.2.3]]></version></module>", encoding="utf-8")
    (tmp_path / "composer.lock").write_text(json.dumps({"packages": [{"name": "vendor/package", "version": "v2.0.0"}]}), encoding="utf-8")

    inventory = scan_local_source(tmp_path)

    assert inventory.network_access is False
    assert inventory.executed_source_code is False
    assert [(item.kind, item.name, item.version) for item in inventory.components] == [
        ("prestashop-core", "prestashop/prestashop", "8.2.8"),
        ("prestashop-module", "samplemodule", "1.2.3"),
        ("composer-package", "vendor/package", "v2.0.0"),
    ]
    assert all(item.evidence_path for item in inventory.components)
    assert all(item.evidence_sha256 and len(item.evidence_sha256) == 64 for item in inventory.components)
    sbom = render_cyclonedx(inventory)
    assert sbom["bomFormat"] == "CycloneDX"
    assert sbom["specVersion"] == "1.6"
    assert sbom["components"][2]["purl"] == "pkg:composer/vendor/package@2.0.0"
    assert render_cyclonedx(inventory)["serialNumber"] == sbom["serialNumber"]
    assert sbom["metadata"]["tools"]["components"][0]["name"] == "LOGIALOG PrestaShop Security Auditor"
    assert sbom["metadata"]["tools"]["components"][0]["version"] == VERSION


def test_local_scan_does_not_follow_symlinked_modules(tmp_path):
    modules = tmp_path / "modules"
    outside = tmp_path.parent / "outside-module"
    modules.mkdir()
    outside.mkdir(exist_ok=True)
    link = modules / "linked"
    try:
        link.symlink_to(outside, target_is_directory=True)
    except OSError:
        return

    inventory = scan_local_source(tmp_path)
    assert all(item.name != "linked" for item in inventory.components)


def test_local_scan_never_invents_unknown_core_version(tmp_path):
    inventory = scan_local_source(tmp_path)
    assert not inventory.components
    assert "aucune version n'a été déduite" in inventory.warnings[0]


def test_local_scan_rejects_malformed_composer_lock(tmp_path):
    (tmp_path / "composer.lock").write_text('{"packages": "invalid"}', encoding="utf-8")

    try:
        scan_local_source(tmp_path)
    except ValueError as exc:
        assert "composer.lock invalide" in str(exc)
    else:
        raise AssertionError("Un composer.lock malformé doit être refusé")


def test_local_scan_reports_overrides_and_safe_configuration_flags(tmp_path):
    override = tmp_path / "override" / "classes"
    config = tmp_path / "config"
    install = tmp_path / "install"
    override.mkdir(parents=True)
    config.mkdir()
    install.mkdir()
    (override / "Product.php").write_text("<?php // content must not be exported", encoding="utf-8")
    (config / "defines.inc.php").write_text("<?php define('_PS_MODE_DEV_', true);", encoding="utf-8")

    inventory = scan_local_source(tmp_path)

    assert [(item.category, item.subject, item.status) for item in inventory.observations] == [
        ("override", "Product", "review"),
        ("configuration", "PrestaShop developer mode", "enabled"),
        ("deployment", "Install directory", "review"),
    ]
    serialized = inventory.model_dump_json()
    assert "content must not be exported" not in serialized


def test_local_scan_does_not_export_database_credentials(tmp_path):
    config = tmp_path / "app" / "config"
    config.mkdir(parents=True)
    (config / "parameters.php").write_text("<?php return ['database_password' => 'secret-value'];", encoding="utf-8")

    serialized = scan_local_source(tmp_path).model_dump_json()

    assert "secret-value" not in serialized
    assert "database_password" not in serialized


def test_local_scan_detects_modern_install_version_file(tmp_path):
    install = tmp_path / "install-dev"
    install.mkdir()
    (install / "install_version.php").write_text("<?php define('_PS_INSTALL_VERSION_', '9.3.0');", encoding="utf-8")

    inventory = scan_local_source(tmp_path)

    core = inventory.components[0]
    assert core.version == "9.3.0"
    assert core.detection_method == "ps_install_version_constant"
    assert core.evidence_path == "install-dev/install_version.php"
    assert len(core.evidence_sha256) == 64
