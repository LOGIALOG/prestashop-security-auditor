from __future__ import annotations

import hashlib
import zipfile
from pathlib import Path, PurePosixPath
from typing import Literal

from pydantic import BaseModel, Field


MAX_ARCHIVE_FILES = 50_000
MAX_UNCOMPRESSED_BYTES = 2_000_000_000
MAX_SINGLE_FILE_BYTES = 100_000_000
ADDED_CODE_SUFFIXES = {".php", ".tpl", ".twig", ".js", ".ts"}
IGNORED_SOURCE_PARTS = {".git", "node_modules", "vendor", "cache", "logs", "reports"}


class FileDifference(BaseModel):
    path: str
    status: Literal["modified", "missing", "added"]
    expected_sha256: str | None = None
    actual_sha256: str | None = None


class ArchiveComparison(BaseModel):
    format: Literal["logialog-archive-comparison"] = "logialog-archive-comparison"
    format_version: Literal["1.0"] = "1.0"
    reference_name: str
    checked_files: int
    differences: list[FileDifference] = Field(default_factory=list)
    source_code_executed: Literal[False] = False
    network_access: Literal[False] = False


def _safe_member(name: str) -> PurePosixPath:
    path = PurePosixPath(name.replace("\\", "/"))
    if path.is_absolute() or ".." in path.parts or (path.parts and ":" in path.parts[0]):
        raise ValueError(f"Chemin dangereux dans l'archive: {name}")
    return path


def _sha256_stream(stream) -> str:
    digest = hashlib.sha256()
    while chunk := stream.read(1024 * 1024):
        digest.update(chunk)
    return digest.hexdigest()


def _hash_added_file(root: Path, local_path: Path, remaining_bytes: int) -> tuple[str, int]:
    if local_path.is_symlink() or not local_path.is_file():
        raise ValueError(f"Fichier additionnel non sûr: {local_path}")
    try:
        resolved = local_path.resolve()
        resolved.relative_to(root)
    except (OSError, ValueError) as exc:
        raise ValueError(f"Chemin additionnel hors du checkout: {local_path}") from exc
    try:
        size = resolved.stat().st_size
    except OSError as exc:
        raise ValueError(f"Lecture impossible du fichier additionnel: {local_path}") from exc
    if size > MAX_SINGLE_FILE_BYTES:
        raise ValueError(f"Fichier additionnel trop volumineux: {local_path}")
    if size > remaining_bytes:
        raise ValueError("Checkout refusé: taille cumulée des fichiers additionnels excessive")
    try:
        with resolved.open("rb") as handle:
            digest = _sha256_stream(handle)
            read_size = handle.tell()
    except OSError as exc:
        raise ValueError(f"Lecture impossible du fichier additionnel: {local_path}") from exc
    if read_size != size:
        raise ValueError(f"Fichier additionnel modifié pendant la lecture: {local_path}")
    return digest, read_size


def compare_with_zip(source: Path, reference: Path) -> ArchiveComparison:
    root = source.resolve()
    archive = reference.resolve()
    if not root.is_dir():
        raise ValueError(f"Checkout introuvable: {root}")
    if not archive.is_file() or archive.suffix.casefold() != ".zip":
        raise ValueError("La référence doit être une archive ZIP locale")

    differences: list[FileDifference] = []
    checked = 0
    reference_paths: set[str] = set()
    with zipfile.ZipFile(archive) as handle:
        files = [item for item in handle.infolist() if not item.is_dir()]
        if len(files) > MAX_ARCHIVE_FILES:
            raise ValueError("Archive refusée: trop de fichiers")
        if sum(item.file_size for item in files) > MAX_UNCOMPRESSED_BYTES:
            raise ValueError("Archive refusée: taille décompressée excessive")
        paths = [_safe_member(item.filename) for item in files]
        first_parts = {path.parts[0] for path in paths if len(path.parts) > 1}
        strip_root = len(first_parts) == 1 and all(len(path.parts) > 1 for path in paths)
        for info, member_path in zip(files, paths, strict=True):
            if info.flag_bits & 0x1:
                raise ValueError("Archive chiffrée non prise en charge")
            if info.file_size > MAX_SINGLE_FILE_BYTES:
                raise ValueError(f"Fichier trop volumineux dans l'archive: {info.filename}")
            relative = PurePosixPath(*member_path.parts[1:]) if strip_root else member_path
            reference_paths.add(relative.as_posix())
            destination = (root / Path(*relative.parts)).resolve()
            try:
                destination.relative_to(root)
            except ValueError as exc:
                raise ValueError(f"Chemin hors checkout: {relative}") from exc
            with handle.open(info) as archived_file:
                expected = _sha256_stream(archived_file)
            checked += 1
            if not destination.is_file() or destination.is_symlink():
                differences.append(FileDifference(path=relative.as_posix(), status="missing", expected_sha256=expected))
                continue
            with destination.open("rb") as local_file:
                actual = _sha256_stream(local_file)
            if actual != expected:
                differences.append(FileDifference(path=relative.as_posix(), status="modified", expected_sha256=expected, actual_sha256=actual))
    added_checked = 0
    added_bytes = 0
    for local_path in sorted(root.rglob("*")):
        if not local_path.is_file() or local_path.is_symlink() or local_path.suffix.casefold() not in ADDED_CODE_SUFFIXES:
            continue
        try:
            relative = local_path.resolve().relative_to(root).as_posix()
        except (OSError, ValueError):
            continue
        if any(part.casefold() in IGNORED_SOURCE_PARTS for part in PurePosixPath(relative).parts):
            continue
        added_checked += 1
        if added_checked > MAX_ARCHIVE_FILES:
            raise ValueError("Checkout refusé: trop de fichiers de code additionnels")
        if relative in reference_paths:
            continue
        remaining = MAX_UNCOMPRESSED_BYTES - added_bytes
        digest, size = _hash_added_file(root, local_path, remaining)
        if size > remaining:
            raise ValueError("Checkout refusé: taille cumulée des fichiers additionnels excessive")
        added_bytes += size
        differences.append(FileDifference(path=relative, status="added", actual_sha256=digest))
    differences.sort(key=lambda item: (item.path, item.status))
    return ArchiveComparison(reference_name=archive.name, checked_files=checked, differences=differences)
