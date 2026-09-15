from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from datetime import date
from pathlib import Path
from typing import Sequence

import httpx
from pydantic import ValidationError

from .advisories import MANIFEST_NAME, build_advisory_manifest, validate_advisory_files, validate_advisory_manifest
from .advisory_ingest import propose_advisory
from .archive_verify import compare_with_zip
from .code_review import review_local_php
from .comparison import compare_audits
from .companion import fetch_companion_inventory
from .database import add_history_event, get_audit, get_previous_real_audit, list_history, save_audit, verify_history
from .doctor import run_doctor
from .exports import render_json_export, render_sarif
from .models import AuditRequest, AuditResult, Status
from .manifest_signing import sign_manifest, verify_manifest_signature
from .local_assessment import assess_local_source, render_assessment_cyclonedx, render_assessment_sarif
from .monitoring import evaluate_monitor, incomplete_monitor_result, load_monitor_config
from .multistore import load_multistore_manifest, run_multistore
from .policy import evaluate_policy, load_policy_pack
from .report import save_report
from .report_bundle import create_signed_bundle, verify_signed_bundle
from .report_profile import load_report_profile
from .repository_safety import validate_repository_safety
from .scanner import AuditPolicyError, PassiveScanner
from .scan_plan import build_scan_plan
from .source_scan import render_cyclonedx, scan_local_source

EXIT_OK = 0
EXIT_INVALID_INPUT = 2
EXIT_NOT_FOUND = 3
EXIT_INVALID_ADVISORY = 4
EXIT_RUNTIME_ERROR = 5
EXIT_POLICY_FINDINGS = 10
EXIT_MEANINGFUL_CHANGE = 11
EXIT_DOCTOR_FAILED = 12


def _configure_utf8_streams() -> None:
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            reconfigure(encoding="utf-8", errors="replace")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="logialog", description="Auditeur passif PrestaShop LOGIALOG")
    subcommands = parser.add_subparsers(dest="command", required=True)

    scan = subcommands.add_parser("scan", help="Exécuter un audit passif autorisé")
    scan.add_argument("target")
    scan.add_argument("--authorized", action="store_true", help="Confirmer l'autorisation explicite")
    scan.add_argument("--max-requests", type=int, default=20)
    scan.add_argument("--delay", type=float, default=1.0)
    scan.add_argument("--public-page", action="append", default=[])
    scan.add_argument("--format", choices=("json", "sarif"), default="json")
    scan.add_argument("--output", type=Path)
    scan.add_argument("--fail-on-confirmed", action="store_true")

    plan = subcommands.add_parser("plan", help="Afficher le périmètre d’un audit sans accès réseau")
    plan.add_argument("target")
    plan.add_argument("--authorized", action="store_true", help="Confirmer l'autorisation explicite")
    plan.add_argument("--max-requests", type=int, default=20)
    plan.add_argument("--delay", type=float, default=1.0)
    plan.add_argument("--public-page", action="append", default=[])
    plan.add_argument("--output", type=Path)

    doctor = subcommands.add_parser("doctor", help="Vérifier la préparation locale sans accès réseau")
    doctor.add_argument("--root", type=Path, default=Path.cwd())
    doctor.add_argument("--output", type=Path)

    export = subcommands.add_parser("export", help="Exporter un audit enregistré")
    export.add_argument("audit_id")
    export.add_argument("--format", choices=("json", "sarif"), default="json")
    export.add_argument("--output", type=Path)

    report = subcommands.add_parser("report", help="Générer un rapport HTML avec un profil validé")
    report_commands = report.add_subparsers(dest="report_command", required=True)
    report_render = report_commands.add_parser("render", help="Rendre un rapport réutilisable ou white-label")
    report_render.add_argument("audit_id")
    report_render.add_argument("--profile", type=Path, required=True)
    report_render.add_argument("--output", type=Path, required=True)

    multistore = subcommands.add_parser("multistore", help="Gérer des périmètres de boutiques strictement séparés")
    multistore_commands = multistore.add_subparsers(dest="multistore_command", required=True)
    multistore_validate = multistore_commands.add_parser("validate", help="Valider un inventaire multistore sans lancer de requête")
    multistore_validate.add_argument("--manifest", type=Path, required=True)
    multistore_scan = multistore_commands.add_parser("scan", help="Auditer séquentiellement chaque boutique autorisée")
    multistore_scan.add_argument("--manifest", type=Path, required=True)
    multistore_scan.add_argument("--output", type=Path, required=True)
    multistore_scan.add_argument("--fail-on-confirmed", action="store_true")

    bundle = subcommands.add_parser("bundle", help="Créer et vérifier des bundles de rapport signés")
    bundle_commands = bundle.add_subparsers(dest="bundle_command", required=True)
    bundle_create = bundle_commands.add_parser("create", help="Créer un ZIP portable signé Ed25519")
    bundle_create.add_argument("audit_id")
    bundle_create.add_argument("--output", type=Path, required=True)
    bundle_create.add_argument("--private-key", type=Path, required=True)
    bundle_create.add_argument("--password-env")
    bundle_create.add_argument("--profile", type=Path)
    bundle_verify = bundle_commands.add_parser("verify", help="Vérifier la structure, les hashes et la signature")
    bundle_verify.add_argument("--bundle", type=Path, required=True)
    bundle_verify.add_argument("--public-key", type=Path, required=True)

    policy = subcommands.add_parser("policy", help="Valider et appliquer des policy packs locaux")
    policy_commands = policy.add_subparsers(dest="policy_command", required=True)
    policy_validate = policy_commands.add_parser("validate", help="Valider un policy pack sans audit")
    policy_validate.add_argument("--policy", type=Path, required=True)
    policy_evaluate = policy_commands.add_parser("evaluate", help="Évaluer un audit enregistré sans modifier ses résultats")
    policy_evaluate.add_argument("audit_id")
    policy_evaluate.add_argument("--policy", type=Path, required=True)
    policy_evaluate.add_argument("--output", type=Path)

    monitor = subcommands.add_parser("monitor", help="Exécuter un contrôle local planifiable et signaler les changements utiles")
    monitor_commands = monitor.add_subparsers(dest="monitor_command", required=True)
    monitor_validate = monitor_commands.add_parser("validate", help="Valider la configuration sans envoyer de requête")
    monitor_validate.add_argument("--config", type=Path, required=True)
    monitor_run = monitor_commands.add_parser("run", help="Créer un audit et le comparer au dernier audit réel")
    monitor_run.add_argument("--config", type=Path, required=True)
    monitor_run.add_argument("--output", type=Path, required=True)

    companion = subcommands.add_parser("companion", help="Lire l’inventaire authentifié du module optionnel")
    companion_commands = companion.add_subparsers(dest="companion_command", required=True)
    companion_fetch = companion_commands.add_parser("fetch", help="Récupérer un inventaire GET signé HMAC")
    companion_fetch.add_argument("--endpoint", required=True)
    companion_fetch.add_argument("--secret-env", required=True)
    companion_fetch.add_argument("--authorized", action="store_true")
    companion_fetch.add_argument("--output", type=Path, required=True)

    history = subcommands.add_parser("history", help="Consulter et enrichir le journal d’équipe chaîné")
    history_commands = history.add_subparsers(dest="history_command", required=True)
    history_add = history_commands.add_parser("add", help="Ajouter une revue attribuée à un audit")
    history_add.add_argument("audit_id")
    history_add.add_argument("--actor", required=True)
    history_add.add_argument("--event", choices=("reviewed","remediation_started","remediation_completed","risk_accepted"), required=True)
    history_add.add_argument("--note", default="")
    history_list = history_commands.add_parser("list", help="Exporter le journal complet ou celui d’un audit")
    history_list.add_argument("--audit-id")
    history_list.add_argument("--output", type=Path)
    history_commands.add_parser("verify", help="Vérifier toute la chaîne SHA-256")

    advisories = subcommands.add_parser("advisories", help="Gérer les données de vulnérabilités")
    advisory_commands = advisories.add_subparsers(dest="advisory_command", required=True)
    validate = advisory_commands.add_parser("validate", help="Valider tous les advisory JSON")
    validate.add_argument("--directory", type=Path)
    manifest = advisory_commands.add_parser("manifest", help="Générer le manifest SHA-256 du snapshot")
    manifest.add_argument("--directory", type=Path)
    manifest.add_argument("--output", type=Path)
    propose = advisory_commands.add_parser("propose", help="Normaliser un payload local dans une file de revue")
    propose.add_argument("--adapter", choices=("friendsofpresta", "prestashop"), required=True)
    propose.add_argument("--input", type=Path, required=True)
    propose.add_argument("--retrieved-at", type=date.fromisoformat, required=True)
    propose.add_argument("--output", type=Path, required=True)
    sign = advisory_commands.add_parser("sign", help="Signer le manifest avec une clé privée Ed25519 locale")
    sign.add_argument("--manifest", type=Path, required=True)
    sign.add_argument("--private-key", type=Path, required=True)
    sign.add_argument("--password-env")
    sign.add_argument("--output", type=Path, required=True)
    verify = advisory_commands.add_parser("verify-signature", help="Vérifier la signature Ed25519 du manifest")
    verify.add_argument("--manifest", type=Path, required=True)
    verify.add_argument("--signature", type=Path, required=True)
    verify.add_argument("--public-key", type=Path, required=True)

    source = subcommands.add_parser("source", help="Analyser un checkout local sans exécuter son code")
    source_commands = source.add_subparsers(dest="source_command", required=True)
    source_scan = source_commands.add_parser("scan", help="Inventorier PrestaShop, modules et Composer")
    source_scan.add_argument("path", type=Path)
    source_scan.add_argument("--format", choices=("json", "cyclonedx"), default="json")
    source_scan.add_argument("--output", type=Path)
    source_verify = source_commands.add_parser("verify", help="Comparer le checkout à une archive ZIP de confiance")
    source_verify.add_argument("path", type=Path)
    source_verify.add_argument("--reference", type=Path, required=True)
    source_verify.add_argument("--output", type=Path)
    source_review = source_commands.add_parser("review", help="Repérer des patterns PHP à revoir sans exécuter le code")
    source_review.add_argument("path", type=Path)
    source_review.add_argument("--output", type=Path)
    source_assess = source_commands.add_parser("assess", help="Corréler les versions locales avec le snapshot advisory vérifié")
    source_assess.add_argument("path", type=Path)
    source_assess.add_argument("--advisories", type=Path)
    source_assess.add_argument("--format", choices=("json", "sarif", "cyclonedx"), default="json")
    source_assess.add_argument("--output", type=Path)
    source_assess.add_argument("--fail-on-affected", action="store_true")

    repository = subcommands.add_parser("repository", help="Vérifier la sécurité des fichiers avant publication")
    repository_commands = repository.add_subparsers(dest="repository_command", required=True)
    repository_validate = repository_commands.add_parser("validate", help="Refuser artifacts locaux et domaines réels dans les fixtures")
    repository_validate.add_argument("--root", type=Path, default=Path.cwd())
    return parser


def _render(audit: AuditResult, output_format: str) -> dict:
    return render_sarif(audit) if output_format == "sarif" else render_json_export(audit)


def _emit(payload: dict, destination: Path | None) -> None:
    content = json.dumps(payload, ensure_ascii=False, indent=2) + "\n"
    if destination:
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(content, encoding="utf-8")
    else:
        sys.stdout.write(content)


async def _scan(args: argparse.Namespace) -> int:
    request = AuditRequest(
        target=args.target,
        authorization_confirmed=args.authorized,
        max_requests=args.max_requests,
        delay_seconds=args.delay,
        public_pages=args.public_page,
    )
    audit = await PassiveScanner().run(request)
    path, digest = save_report(audit)
    audit.report_path, audit.report_sha256 = path, digest
    save_audit(audit)
    _emit(_render(audit, args.format), args.output)
    if audit.scan_completeness != "COMPLETED":
        return EXIT_RUNTIME_ERROR
    if args.fail_on_confirmed and any(item.status == Status.CONFIRMED for item in audit.findings):
        return EXIT_POLICY_FINDINGS
    return EXIT_OK


async def _scan_multistore(args: argparse.Namespace, manifest) -> int:
    batch = await run_multistore(manifest)
    for shop in batch.shops:
        path, digest = save_report(shop.audit)
        shop.audit.report_path, shop.audit.report_sha256 = path, digest
        save_audit(shop.audit)
    _emit(batch.portable_export(), args.output)
    if args.fail_on_confirmed and any(
        item.status == Status.CONFIRMED for shop in batch.shops for item in shop.audit.findings
    ):
        return EXIT_POLICY_FINDINGS
    return EXIT_OK


async def _run_monitor(args:argparse.Namespace,config)->int:
    audit=await PassiveScanner().run(config.audit_request())
    if audit.scan_completeness != "COMPLETED":
        path,digest=save_report(audit)
        audit.report_path,audit.report_sha256=path,digest
        save_audit(audit)
        _emit(incomplete_monitor_result(config,audit).model_dump(mode="json"),args.output)
        return EXIT_RUNTIME_ERROR
    comparison=compare_audits(audit,get_previous_real_audit(audit))
    path,digest=save_report(audit)
    audit.report_path,audit.report_sha256=path,digest
    save_audit(audit)
    result=evaluate_monitor(config,audit,comparison)
    _emit(result.model_dump(mode="json"),args.output)
    return EXIT_MEANINGFUL_CHANGE if result.notification_required else EXIT_OK


async def _fetch_companion(args:argparse.Namespace,secret:str)->int:
    inventory=await fetch_companion_inventory(args.endpoint,secret,args.authorized)
    _emit({"format":"logialog-companion-inventory","format_version":"1.0","inventory":inventory.model_dump(mode="json")},args.output)
    return EXIT_OK


def main(argv: Sequence[str] | None = None) -> int:
    _configure_utf8_streams()
    args = build_parser().parse_args(argv)
    try:
        if args.command == "doctor":
            report = run_doctor(args.root)
            _emit(report.model_dump(mode="json"), args.output)
            return EXIT_OK if report.ready else EXIT_DOCTOR_FAILED
        if args.command == "plan":
            request = AuditRequest(
                target=args.target,
                authorization_confirmed=args.authorized,
                max_requests=args.max_requests,
                delay_seconds=args.delay,
                public_pages=args.public_page,
            )
            _emit(build_scan_plan(request).model_dump(mode="json"), args.output)
            return EXIT_OK
        if args.command == "advisories":
            if args.advisory_command == "sign":
                password_value = os.environ.get(args.password_env) if args.password_env else None
                if args.password_env and password_value is None:
                    raise ValueError(f"Variable de mot de passe absente: {args.password_env}")
                password = password_value.encode() if password_value is not None else None
                _emit(sign_manifest(args.manifest, args.private_key, password).model_dump(mode="json"), args.output)
                sys.stdout.write(f"Signature Ed25519 créée: {args.output}\n")
                return EXIT_OK
            if args.advisory_command == "verify-signature":
                envelope = verify_manifest_signature(args.manifest, args.signature, args.public_key)
                sys.stdout.write(f"Signature Ed25519 valide; key_id={envelope.key_id}.\n")
                return EXIT_OK
            if args.advisory_command == "propose":
                payload = json.loads(args.input.read_text(encoding="utf-8"))
                if not isinstance(payload, dict):
                    raise ValueError("Le payload upstream doit être un objet JSON")
                _emit(propose_advisory(args.adapter, payload, args.retrieved_at).model_dump(mode="json"), args.output)
                sys.stdout.write(f"Proposition créée pour revue: {args.output}\n")
                return EXIT_OK
            if args.advisory_command == "manifest":
                base = args.directory or Path(__file__).resolve().parents[2] / "advisories"
                destination = args.output or base / MANIFEST_NAME
                _emit(build_advisory_manifest(base), destination)
                sys.stdout.write(f"Manifest généré: {destination}\n")
                return EXIT_OK
            paths = validate_advisory_files(args.directory)
            validate_advisory_manifest(args.directory)
            sys.stdout.write(f"{len(paths)} advisory file(s) et manifest validés.\n")
            return EXIT_OK
        if args.command == "export":
            audit = get_audit(args.audit_id)
            if audit is None:
                sys.stderr.write(f"Audit introuvable: {args.audit_id}\n")
                return EXIT_NOT_FOUND
            _emit(_render(audit, args.format), args.output)
            return EXIT_OK
        if args.command == "report":
            audit = get_audit(args.audit_id)
            if audit is None:
                sys.stderr.write(f"Audit introuvable: {args.audit_id}\n")
                return EXIT_NOT_FOUND
            _, digest = save_report(audit, load_report_profile(args.profile), args.output)
            sys.stdout.write(f"Rapport HTML créé: {args.output} (SHA-256 {digest})\n")
            return EXIT_OK
        if args.command == "multistore":
            manifest = load_multistore_manifest(args.manifest)
            if args.multistore_command == "validate":
                sys.stdout.write(f"Manifest multistore valide; {len(manifest.shops)} boutique(s), budget {sum(shop.max_requests for shop in manifest.shops)} requêtes.\n")
                return EXIT_OK
            return asyncio.run(_scan_multistore(args, manifest))
        if args.command == "bundle":
            if args.bundle_command == "verify":
                result = verify_signed_bundle(args.bundle, args.public_key)
                sys.stdout.write(f"Bundle signé valide; audit={result.audit_id}, key_id={result.key_id}, fichiers={result.file_count}.\n")
                return EXIT_OK
            audit = get_audit(args.audit_id)
            if audit is None:
                sys.stderr.write(f"Audit introuvable: {args.audit_id}\n")
                return EXIT_NOT_FOUND
            password_value = os.environ.get(args.password_env) if args.password_env else None
            if args.password_env and password_value is None:
                raise ValueError(f"Variable de mot de passe absente: {args.password_env}")
            profile = load_report_profile(args.profile) if args.profile else None
            manifest = create_signed_bundle(audit,args.output,args.private_key,password_value.encode() if password_value is not None else None,profile)
            sys.stdout.write(f"Bundle Ed25519 créé: {args.output} ({len(manifest.files)} fichiers).\n")
            return EXIT_OK
        if args.command == "policy":
            policy_pack = load_policy_pack(args.policy)
            if args.policy_command == "validate":
                sys.stdout.write(f"Policy pack valide: {policy_pack.policy_id}.\n")
                return EXIT_OK
            audit = get_audit(args.audit_id)
            if audit is None:
                sys.stderr.write(f"Audit introuvable: {args.audit_id}\n")
                return EXIT_NOT_FOUND
            evaluation = evaluate_policy(audit,policy_pack)
            _emit(evaluation.model_dump(mode="json"),args.output)
            return EXIT_OK if evaluation.decision=="PASS" else EXIT_POLICY_FINDINGS
        if args.command == "monitor":
            config=load_monitor_config(args.config)
            if args.monitor_command=="validate":
                sys.stdout.write(f"Monitoring valide: {config.monitor_id}; budget {config.max_requests} requêtes GET.\n")
                return EXIT_OK
            return asyncio.run(_run_monitor(args,config))
        if args.command == "companion":
            secret=os.environ.get(args.secret_env)
            if secret is None:
                raise ValueError(f"Variable de secret absente: {args.secret_env}")
            return asyncio.run(_fetch_companion(args,secret))
        if args.command == "history":
            if args.history_command=="verify":
                count=verify_history()
                sys.stdout.write(f"Chaîne d’historique valide; {count} événement(s).\n")
                return EXIT_OK
            if args.history_command=="list":
                _emit({"format":"logialog-team-history","format_version":"1.0","events":list_history(args.audit_id)},args.output)
                return EXIT_OK
            event=add_history_event(args.audit_id,args.event,args.actor,args.note)
            _emit({"format":"logialog-team-history-event","format_version":"1.0","event":event},None)
            return EXIT_OK
        if args.command == "source":
            if args.source_command == "verify":
                _emit(compare_with_zip(args.path, args.reference).model_dump(mode="json"), args.output)
                return EXIT_OK
            if args.source_command == "review":
                _emit(review_local_php(args.path).model_dump(mode="json"), args.output)
                return EXIT_OK
            if args.source_command == "assess":
                assessment = assess_local_source(args.path, args.advisories)
                if args.format == "sarif":
                    payload = render_assessment_sarif(assessment)
                elif args.format == "cyclonedx":
                    payload = render_assessment_cyclonedx(assessment)
                else:
                    payload = assessment.model_dump(mode="json")
                _emit(payload, args.output)
                if args.fail_on_affected and assessment.affected_count:
                    return EXIT_POLICY_FINDINGS
                return EXIT_OK
            inventory = scan_local_source(args.path)
            payload = render_cyclonedx(inventory) if args.format == "cyclonedx" else inventory.model_dump(mode="json")
            _emit(payload, args.output)
            return EXIT_OK
        if args.command == "repository":
            checked = validate_repository_safety(args.root)
            sys.stdout.write(f"Repository safety validée; {len(checked)} fixture(s) contrôlée(s).\n")
            return EXIT_OK
        return asyncio.run(_scan(args))
    except (ValidationError, AuditPolicyError, ValueError) as exc:
        code = EXIT_INVALID_ADVISORY if args.command == "advisories" else EXIT_INVALID_INPUT
        sys.stderr.write(f"Erreur: {exc}\n")
        return code
    except (OSError, json.JSONDecodeError, httpx.HTTPError) as exc:
        code = EXIT_INVALID_ADVISORY if args.command == "advisories" else EXIT_RUNTIME_ERROR
        sys.stderr.write(f"Erreur: {exc}\n")
        return code


if __name__ == "__main__":
    raise SystemExit(main())
