from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Literal
from uuid import NAMESPACE_URL, uuid5

from pydantic import BaseModel, Field


class LocalComponent(BaseModel):
    kind: Literal["prestashop-core", "prestashop-module", "composer-package"]
    name: str
    version: str | None = None
    relative_path: str
    detection_method: str


class LocalObservation(BaseModel):
    category: Literal["override", "configuration", "deployment"]
    subject: str
    status: Literal["present", "enabled", "disabled", "review"]
    relative_path: str
    interpretation: str
    detection_method: str


class LocalSourceInventory(BaseModel):
    format: Literal["logialog-source-inventory"] = "logialog-source-inventory"
    format_version: Literal["1.0"] = "1.0"
    root_name: str
    components: list[LocalComponent] = Field(default_factory=list)
    observations: list[LocalObservation] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    network_access: Literal[False] = False
    executed_source_code: Literal[False] = False


VERSION_PATTERN = re.compile(r"_PS_VERSION_[\s'\",()]+(\d+(?:\.\d+){1,3})")
PHP_MODULE_VERSION = re.compile(r"\$this->version\s*=\s*['\"]([^'\"]+)['\"]")
XML_MODULE_VERSION = re.compile(r"<version>\s*(?:<!\[CDATA\[)?\s*([^<\]]+)")
DEV_MODE_PATTERN = re.compile(r"define\s*\(\s*['\"]_PS_MODE_DEV_['\"]\s*,\s*(true|false)", re.IGNORECASE)
MAX_OVERRIDE_FILES = 5_000


def _safe_file(root: Path, path: Path) -> bool:
    try:
        path.resolve().relative_to(root)
        return path.is_file()
    except (OSError, ValueError):
        return False


def _safe_directory(root: Path, path: Path) -> bool:
    try:
        path.resolve().relative_to(root)
        return path.is_dir() and not path.is_symlink()
    except (OSError, ValueError):
        return False


def _read_limited(path: Path, limit: int = 1_000_000) -> str:
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        return handle.read(limit)


def _core_component(root: Path) -> LocalComponent | None:
    candidates = [root / "config" / "settings.inc.php", root / "app" / "AppKernel.php"]
    for path in candidates:
        if not _safe_file(root, path):
            continue
        match = VERSION_PATTERN.search(_read_limited(path))
        if match:
            return LocalComponent(kind="prestashop-core", name="prestashop/prestashop", version=match.group(1), relative_path=path.relative_to(root).as_posix(), detection_method="ps_version_constant")
    return None


def _module_component(root: Path, module_dir: Path) -> LocalComponent:
    version = None
    method = "directory_name"
    config = module_dir / "config.xml"
    main_php = module_dir / f"{module_dir.name}.php"
    if _safe_file(root, config):
        match = XML_MODULE_VERSION.search(_read_limited(config))
        if match:
            version, method = match.group(1).strip(), "config_xml"
    if version is None and _safe_file(root, main_php):
        match = PHP_MODULE_VERSION.search(_read_limited(main_php))
        if match:
            version, method = match.group(1).strip(), "module_php_assignment"
    return LocalComponent(kind="prestashop-module", name=module_dir.name, version=version, relative_path=module_dir.relative_to(root).as_posix(), detection_method=method)


def _scan_overrides(root: Path, warnings: list[str]) -> list[LocalObservation]:
    override_root = root / "override"
    if not _safe_directory(root, override_root):
        return []
    observations: list[LocalObservation] = []
    for path in sorted(override_root.rglob("*.php")):
        if len(observations) >= MAX_OVERRIDE_FILES:
            warnings.append(f"Inventaire des overrides limité à {MAX_OVERRIDE_FILES} fichiers.")
            break
        if _safe_file(root, path) and not path.is_symlink():
            observations.append(LocalObservation(category="override", subject=path.stem, status="review", relative_path=path.relative_to(root).as_posix(), interpretation="Override PHP présent; revue manuelle recommandée après les mises à jour du cœur ou des modules.", detection_method="override_php_path"))
    return observations


def _scan_configuration(root: Path) -> list[LocalObservation]:
    observations: list[LocalObservation] = []
    defines = root / "config" / "defines.inc.php"
    if _safe_file(root, defines):
        match = DEV_MODE_PATTERN.search(_read_limited(defines))
        if match:
            enabled = match.group(1).casefold() == "true"
            observations.append(LocalObservation(category="configuration", subject="PrestaShop developer mode", status="enabled" if enabled else "disabled", relative_path=defines.relative_to(root).as_posix(), interpretation="Mode développeur activé en configuration." if enabled else "Mode développeur explicitement désactivé.", detection_method="ps_mode_dev_constant"))
    install_dir = root / "install"
    if _safe_directory(root, install_dir):
        observations.append(LocalObservation(category="deployment", subject="Install directory", status="review", relative_path="install", interpretation="Répertoire d’installation présent dans le checkout; confirmer qu’il n’est pas déployé publiquement.", detection_method="directory_presence"))
    return observations


def scan_local_source(source: Path) -> LocalSourceInventory:
    root = source.expanduser().resolve()
    if not root.is_dir():
        raise ValueError(f"Répertoire source introuvable: {root}")
    components: list[LocalComponent] = []
    warnings: list[str] = []
    core = _core_component(root)
    if core:
        components.append(core)
    else:
        warnings.append("Version du cœur PrestaShop non détectée; aucune version n'a été déduite.")

    modules = root / "modules"
    if _safe_directory(root, modules):
        for module_dir in sorted(modules.iterdir(), key=lambda item: item.name.casefold()):
            if _safe_directory(root, module_dir):
                components.append(_module_component(root, module_dir))

    lockfile = root / "composer.lock"
    if _safe_file(root, lockfile):
        payload = json.loads(_read_limited(lockfile, 20_000_000))
        packages = payload.get("packages", [])
        packages_dev = payload.get("packages-dev", [])
        if not isinstance(packages, list) or not isinstance(packages_dev, list):
            raise ValueError("composer.lock invalide: packages doit être une liste")
        for package in [*packages, *packages_dev]:
            if not isinstance(package, dict):
                raise ValueError("composer.lock invalide: package non structuré")
            name, version = package.get("name"), package.get("version")
            if isinstance(name, str):
                components.append(LocalComponent(kind="composer-package", name=name, version=version if isinstance(version, str) else None, relative_path="composer.lock", detection_method="composer_lock"))
    observations = _scan_overrides(root, warnings)
    observations.extend(_scan_configuration(root))
    return LocalSourceInventory(root_name=root.name, components=components, observations=observations, warnings=warnings)


def render_cyclonedx(inventory: LocalSourceInventory) -> dict:
    identity = "|".join(f"{item.kind}:{item.name}:{item.version or ''}" for item in inventory.components)
    components = []
    for item in inventory.components:
        component_type = "application" if item.kind == "prestashop-core" else "library"
        component = {"type": component_type, "name": item.name, "properties": [{"name": "logialog:kind", "value": item.kind}, {"name": "logialog:path", "value": item.relative_path}, {"name": "logialog:detection-method", "value": item.detection_method}]}
        if item.version:
            component["version"] = item.version
        if item.kind == "composer-package" and item.version:
            component["purl"] = f"pkg:composer/{item.name}@{item.version.lstrip('v')}"
        components.append(component)
    return {"bomFormat": "CycloneDX", "specVersion": "1.6", "serialNumber": f"urn:uuid:{uuid5(NAMESPACE_URL, identity)}", "version": 1, "metadata": {"tools": {"components": [{"type": "application", "name": "LOGIALOG PrestaShop Security Auditor", "version": "1.3.0"}]}}, "components": components}
