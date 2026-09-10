import json
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse

from .comparison import compare_audits
from .database import get_audit, get_previous_real_audit, init_db, save_audit
from .exports import render_json_export, render_sarif
from .models import AuditComparison, AuditRequest, AuditResult
from .report import render_report, save_report
from .scanner import AuditPolicyError, PassiveScanner

app = FastAPI(title="LOGIALOG PrestaShop Security Auditor", version="1.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["http://127.0.0.1:5173"], allow_methods=["GET", "POST"], allow_headers=["*"])


@app.on_event("startup")
def startup() -> None:
    init_db()


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/api/demo", response_model=AuditResult)
def demo_audit() -> AuditResult:
    fixture = Path(__file__).resolve().parents[1] / "fixtures" / "demo-audit.json"
    return AuditResult.model_validate(json.loads(fixture.read_text(encoding="utf-8")))


@app.get("/api/demo/report", response_class=HTMLResponse)
def demo_report() -> HTMLResponse:
    html, _ = render_report(demo_audit())
    return HTMLResponse(html, headers={"Content-Disposition": "inline; filename=demo-report.html"})


@app.get("/api/demo/export.json")
def demo_json_export() -> JSONResponse:
    return _download_json(render_json_export(demo_audit()), "logialog-demo-audit.json")


@app.get("/api/demo/export.sarif")
def demo_sarif_export() -> JSONResponse:
    return _download_json(render_sarif(demo_audit()), "logialog-demo-audit.sarif")


@app.post("/api/audits", response_model=AuditResult)
async def create_audit(request: AuditRequest) -> AuditResult:
    try:
        result = await PassiveScanner().run(request)
    except (AuditPolicyError, OSError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    path, digest = save_report(result)
    result.report_path, result.report_sha256 = path, digest
    save_audit(result)
    return result


@app.get("/api/audits/{audit_id}", response_model=AuditResult)
def read_audit(audit_id: str) -> AuditResult:
    result = get_audit(audit_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Audit introuvable")
    return result


@app.get("/api/audits/{audit_id}/report", response_class=HTMLResponse)
def report(audit_id: str) -> HTMLResponse:
    result = read_audit(audit_id)
    html, _ = render_report(result)
    return HTMLResponse(html, headers={"Content-Disposition": f"inline; filename=audit-{audit_id}.html"})


@app.get("/api/audits/{audit_id}/export.json")
def audit_json_export(audit_id: str) -> JSONResponse:
    return _download_json(render_json_export(read_audit(audit_id)), f"audit-{audit_id}.json")


@app.get("/api/audits/{audit_id}/export.sarif")
def audit_sarif_export(audit_id: str) -> JSONResponse:
    return _download_json(render_sarif(read_audit(audit_id)), f"audit-{audit_id}.sarif")


@app.get("/api/audits/{audit_id}/comparison", response_model=AuditComparison)
def audit_comparison(audit_id: str) -> AuditComparison:
    current = read_audit(audit_id)
    if current.is_demo:
        raise HTTPException(status_code=400, detail="La démonstration ne peut pas être comparée")
    return compare_audits(current, get_previous_real_audit(current))


def _download_json(payload: dict, filename: str) -> JSONResponse:
    return JSONResponse(payload, headers={"Content-Disposition": f'attachment; filename="{filename}"'})


@app.get("/api/lab")
def lab_data() -> dict:
    return {"local_only": True, "banner": "LABORATOIRE LOCAL — DONNÉES FICTIVES — AUCUNE EXPLOITATION DU SITE CLIENT.", "unsafe_concept": "SELECT … WHERE id = [entrée non validée]", "safe_concept": "SELECT … WHERE id = ? avec paramètre typé", "fictional_data": {"articles": 4, "accounts": 3, "orders": 6}, "impacts": ["Lecture de données", "Altération de données", "Vol de sessions", "Web skimmer si une chaîne supplémentaire existe"], "fixes": ["Requêtes préparées", "Validation stricte", "Mise à jour vers une version corrigée", "Archive officielle à la place d’une copie nulled"]}
