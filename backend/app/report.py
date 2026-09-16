from __future__ import annotations

import hashlib
from base64 import b64encode
from functools import lru_cache
from html import escape
from pathlib import Path

from .models import AuditResult
from .report_profile import ReportProfile
from .version import VERSION

ROOT = Path(__file__).resolve().parents[2]
DISCLAIMER = "Cette démonstration illustre l’impact potentiel de la vulnérabilité publiée. Elle ne constitue pas une preuve que le site client a été exploité ou que sa version installée est vulnérable."
DEMO_WATERMARK = "DONNÉES FICTIVES — MODE DÉMONSTRATION — NE CONSTITUE PAS UN AUDIT RÉEL."
ENGINE_NAME = "LOGIALOG PrestaShop Security Auditor"
ENGINE_VERSION = VERSION
DEFAULT_LOGO_PATH = ROOT / "frontend" / "public" / "brand" / "logialog-full.png"
DEFAULT_MARK_PATH = ROOT / "frontend" / "public" / "brand" / "logialog-mark.png"


@lru_cache(maxsize=1)
def _default_logo_data_uri() -> str | None:
    """Embed the official logo so saved reports remain fully portable."""
    try:
        encoded = b64encode(DEFAULT_LOGO_PATH.read_bytes()).decode("ascii")
    except OSError:
        return None
    return f"data:image/png;base64,{encoded}"


@lru_cache(maxsize=1)
def _default_mark_data_uri() -> str | None:
    try:
        encoded = b64encode(DEFAULT_MARK_PATH.read_bytes()).decode("ascii")
    except OSError:
        return None
    return f"data:image/png;base64,{encoded}"


def render_report(audit: AuditResult, profile: ReportProfile | None = None) -> tuple[str, str]:
    profile = profile or ReportProfile()
    rows = "".join(
        f"<tr><td data-label='Sujet'>{escape(finding.subject)}</td>"
        f"<td data-label='Statut'>{finding.status.value}</td>"
        f"<td data-label='Sévérité'>{escape(finding.severity)}</td>"
        f"<td data-label='Interprétation'>{escape(finding.interpretation)}</td>"
        f"<td data-label='URL source'>{escape(finding.evidence[0].url)}</td></tr>"
        for finding in audit.findings
    )
    watermark = f"<div class='watermark'>{DEMO_WATERMARK}</div>" if audit.is_demo else ""
    logo_uri = profile.logo_data_uri or _default_logo_data_uri()
    logo_class = "logo" if profile.logo_data_uri else "logo default-logo"
    logo = (
        f"<div class='logo-frame'><img class='{logo_class}' src='{logo_uri}' alt='{escape(profile.brand_name)}'></div>"
        if logo_uri
        else ""
    )
    contact = (
        f"<a class='contact' href='{escape(str(profile.contact_url))}'>{escape(str(profile.contact_url))}</a>"
        if profile.contact_url
        else ""
    )
    subtitle = "Rapport de démonstration" if audit.is_demo else profile.report_title
    completeness = "Complet" if audit.scan_completeness == "COMPLETED" else "Incomplet — aucune décision PASS autorisée"
    favicon = f"<link rel='icon' type='image/png' href='{_default_mark_data_uri()}'>" if _default_mark_data_uri() else ""
    html = f"""<!doctype html>
<html lang='fr'>
<head>
<meta charset='utf-8'>
<meta name='generator' content='{ENGINE_NAME} {ENGINE_VERSION}'>
<meta name='logialog:engine' content='{ENGINE_NAME}'>
<meta name='logialog:engine-version' content='{ENGINE_VERSION}'>
<meta name='logialog:report-profile-schema' content='{profile.schema_version}'>
<meta name='theme-color' content='{profile.primary_color}'>
{favicon}
<title>{escape(subtitle)} — {escape(profile.brand_name)}</title>
<style>
:root{{--primary:{profile.primary_color};--accent:{profile.accent_color}}}
*{{box-sizing:border-box}}body{{font:14px system-ui,-apple-system,"Segoe UI",sans-serif;color:#0f2744;background:#f8fafc;margin:0;line-height:1.5}}
.report-shell{{max-width:1120px;margin:0 auto;padding:36px}}h1{{color:var(--primary);font-size:26px;margin:0 0 4px}}h2{{color:#0f2744;margin:28px 0 10px}}
.identity{{display:flex;align-items:center;gap:22px;padding:22px;border:1px solid #e3edf7;border-top:5px solid var(--accent);border-radius:12px;background:white}}
.logo-frame{{width:230px;height:96px;overflow:hidden;border:1px solid #e3edf7;border-radius:10px;background:white;flex:0 0 auto}}
.logo{{display:block;width:100%;height:100%;object-fit:contain}}.default-logo{{object-fit:cover;object-position:50% 42%}}
.contact{{color:var(--primary);font-weight:650}}.watermark{{position:sticky;top:0;z-index:5;padding:14px 20px;background:#b54708;color:white;font-weight:800;text-align:center;letter-spacing:.02em}}
.meta,.box{{padding:20px;border:1px solid #e3edf7;border-radius:12px;margin:16px 0;background:white}}table{{width:100%;border-collapse:collapse;background:white;border:1px solid #e3edf7;border-radius:12px;overflow:hidden}}
td,th{{padding:12px;border-bottom:1px solid #e3edf7;text-align:left;vertical-align:top}}th{{color:var(--primary);background:#eef6ff}}tbody tr:last-child td{{border-bottom:0}}
.lab{{border-left:5px solid var(--accent);background:#f7fff2}}.report-footer{{margin-top:28px;padding-top:18px;border-top:1px solid #e3edf7;color:#5f7087;font-size:12px;overflow-wrap:anywhere}}
@media(max-width:760px){{.report-shell{{padding:20px}}.identity{{align-items:flex-start;flex-direction:column}}.logo-frame{{width:100%;max-width:230px}}table,tbody,tr,td{{display:block}}thead{{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0 0 0 0);white-space:nowrap}}tbody tr{{padding:12px 14px;border-bottom:1px solid #e3edf7}}tbody tr:last-child{{border-bottom:0}}td{{display:grid;grid-template-columns:100px minmax(0,1fr);gap:10px;padding:6px 0;border:0;overflow-wrap:anywhere}}td::before{{content:attr(data-label);color:var(--primary);font-weight:700}}}}
@media print{{body{{background:white}}.report-shell{{max-width:none;padding:20px}}.watermark{{position:fixed;top:0;left:0;right:0}}.identity,.meta,.box,table{{break-inside:avoid}}}}
</style>
</head>
<body data-report-engine='{ENGINE_NAME}' data-report-engine-version='{ENGINE_VERSION}'>
{watermark}
<main class='report-shell'>
<div class='identity'>{logo}<div><h1>{escape(profile.brand_name)}</h1>{contact}</div></div>
<h2>{escape(subtitle)}</h2>
<div class='meta'><b>Domaine :</b> {escape(audit.domain)}<br>
<b>Date UTC :</b> {'Date fictive' if audit.is_demo else audit.completed_at.isoformat()}<br>
<b>Complétude :</b> {completeness}<br>
<b>Périmètre :</b> page d’accueil, robots.txt, pages publiques explicites et assets référencés ({audit.request_count} requêtes GET).<br>
<b>Limites :</b> audit public, passif et non destructif; aucune preuve d’exploitation, aucun POST, aucun contournement.</div>
<h2>Résumé exécutif</h2>
<p>Les résultats séparent strictement les versions affectées confirmées, les éléments à vérifier, les résidus d’assets et les recommandations de durcissement.</p>
<h2>Résultats et preuves</h2>
<table><thead><tr><th>Sujet</th><th>Statut</th><th>Sévérité</th><th>Interprétation</th><th>URL source</th></tr></thead><tbody>{rows}</tbody></table>
<div class='box lab'><h2>Simulation locale séparée</h2><p>{DISCLAIMER}</p></div>
<h2>Plan de remédiation</h2>
<h3>P0</h3><p>Sauvegarder fichiers et base; conserver les logs; identifier les modules de provenance inconnue; les remplacer par des archives officielles; faire une rotation des mots de passe et secrets; rechercher webshells, code obfusqué, overrides et tâches cron inconnues.</p>
<h3>P1</h3><p>Confirmer les versions des modules; mettre à jour PrestaShop; vérifier employés et permissions; auditer les controllers AJAX publics.</p>
<h3>P2</h3><p>Ajouter CSP, HSTS et Permissions-Policy après tests; contrôler les cookies de session; renforcer WAF, logs, alertes et surveillance d’intégrité.</p>
<p><b>Autorisation :</b> le demandeur a confirmé être propriétaire du site ou disposer d’une autorisation explicite.</p>
<footer class='report-footer'><!-- REPORT_HASH_PLACEHOLDER --></footer>
</main>
</body></html>"""
    digest = hashlib.sha256(html.encode()).hexdigest()
    html = html.replace("<!-- REPORT_HASH_PLACEHOLDER -->", f"<b>SHA-256 du rapport :</b> {digest}")
    return html, digest


def save_report(audit: AuditResult, profile: ReportProfile | None = None, destination: Path | None = None) -> tuple[str, str]:
    html, digest = render_report(audit, profile)
    destination = destination or ROOT / "reports" / f"audit-{audit.id}.html"
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(html, encoding="utf-8")
    return str(destination), digest
