import json
import hashlib
import re
import sqlite3
from datetime import datetime,timezone
from pathlib import Path

from .models import AuditResult

ROOT = Path(__file__).resolve().parents[2]
DB_PATH = ROOT / "reports" / "audits.sqlite3"


def init_db() -> None:
    DB_PATH.parent.mkdir(exist_ok=True)
    with sqlite3.connect(DB_PATH) as db:
        version = db.execute("PRAGMA user_version").fetchone()[0]
        if version < 1:
            db.execute("CREATE TABLE IF NOT EXISTS audits (id TEXT PRIMARY KEY, domain TEXT NOT NULL, created_at TEXT NOT NULL, payload TEXT NOT NULL)")
            db.execute("PRAGMA user_version = 1")
        if version < 2:
            db.execute("CREATE TABLE IF NOT EXISTS audit_events (id INTEGER PRIMARY KEY AUTOINCREMENT, audit_id TEXT NOT NULL, domain TEXT NOT NULL, event_type TEXT NOT NULL, actor TEXT NOT NULL, created_at TEXT NOT NULL, details TEXT NOT NULL, previous_hash TEXT NOT NULL, event_hash TEXT NOT NULL UNIQUE)")
            db.execute("PRAGMA user_version = 2")


def _append_event(db:sqlite3.Connection,audit_id:str,domain:str,event_type:str,actor:str,details:dict)->dict:
    if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9._@-]{1,79}",actor):
        raise ValueError("Identifiant opérateur invalide")
    if not re.fullmatch(r"[a-z][a-z0-9._-]{2,63}",event_type):
        raise ValueError("Type d’événement invalide")
    created_at=datetime.now(timezone.utc).isoformat()
    details_json=json.dumps(details,ensure_ascii=False,sort_keys=True,separators=(",",":"))
    row=db.execute("SELECT event_hash FROM audit_events ORDER BY id DESC LIMIT 1").fetchone()
    previous_hash=row[0] if row else "0"*64
    canonical=json.dumps({"audit_id":audit_id,"domain":domain,"event_type":event_type,"actor":actor,"created_at":created_at,"details":json.loads(details_json),"previous_hash":previous_hash},ensure_ascii=False,sort_keys=True,separators=(",",":"))
    event_hash=hashlib.sha256(canonical.encode()).hexdigest()
    db.execute("INSERT INTO audit_events (audit_id,domain,event_type,actor,created_at,details,previous_hash,event_hash) VALUES (?,?,?,?,?,?,?,?)",(audit_id,domain,event_type,actor,created_at,details_json,previous_hash,event_hash))
    return {"audit_id":audit_id,"domain":domain,"event_type":event_type,"actor":actor,"created_at":created_at,"details":json.loads(details_json),"previous_hash":previous_hash,"event_hash":event_hash}


def save_audit(audit: AuditResult) -> None:
    init_db()
    with sqlite3.connect(DB_PATH) as db:
        exists=db.execute("SELECT 1 FROM audits WHERE id = ?",(audit.id,)).fetchone() is not None
        db.execute("INSERT OR REPLACE INTO audits VALUES (?, ?, ?, ?)", (audit.id, audit.domain, audit.completed_at.isoformat(), audit.model_dump_json()))
        _append_event(db,audit.id,audit.domain,"audit_updated" if exists else "audit_created","system",{"demo":audit.is_demo,"request_count":audit.request_count,"score":audit.score.value if audit.score else None})


def add_history_event(audit_id:str,event_type:str,actor:str,note:str="")->dict:
    if len(note)>500 or any(character in note for character in "\r\n"):
        raise ValueError("La note doit tenir sur une ligne de 500 caractères maximum")
    init_db()
    with sqlite3.connect(DB_PATH) as db:
        row=db.execute("SELECT domain FROM audits WHERE id = ?",(audit_id,)).fetchone()
        if row is None:
            raise ValueError(f"Audit introuvable: {audit_id}")
        return _append_event(db,audit_id,row[0],event_type,actor,{"note":note})


def list_history(audit_id:str|None=None)->list[dict]:
    init_db()
    with sqlite3.connect(DB_PATH) as db:
        query="SELECT audit_id,domain,event_type,actor,created_at,details,previous_hash,event_hash FROM audit_events"
        params=()
        if audit_id:
            query+=" WHERE audit_id = ?"
            params=(audit_id,)
        rows=db.execute(query+" ORDER BY id",params).fetchall()
    return [{"audit_id":row[0],"domain":row[1],"event_type":row[2],"actor":row[3],"created_at":row[4],"details":json.loads(row[5]),"previous_hash":row[6],"event_hash":row[7]} for row in rows]


def verify_history()->int:
    events=list_history()
    previous_hash="0"*64
    for event in events:
        if event["previous_hash"]!=previous_hash:
            raise ValueError("Chaîne d’historique interrompue")
        canonical=json.dumps({key:event[key] for key in ("audit_id","domain","event_type","actor","created_at","details","previous_hash")},ensure_ascii=False,sort_keys=True,separators=(",",":"))
        if hashlib.sha256(canonical.encode()).hexdigest()!=event["event_hash"]:
            raise ValueError("Hash d’historique invalide")
        previous_hash=event["event_hash"]
    return len(events)


def get_audit(audit_id: str) -> AuditResult | None:
    init_db()
    with sqlite3.connect(DB_PATH) as db:
        row = db.execute("SELECT payload FROM audits WHERE id = ?", (audit_id,)).fetchone()
    return AuditResult.model_validate_json(row[0]) if row else None


def get_previous_real_audit(audit: AuditResult) -> AuditResult | None:
    if audit.is_demo:
        return None
    init_db()
    with sqlite3.connect(DB_PATH) as db:
        rows = db.execute(
            "SELECT payload FROM audits WHERE domain = ? AND id <> ? AND created_at < ? "
            "ORDER BY created_at DESC",
            (audit.domain, audit.id, audit.completed_at.isoformat()),
        ).fetchall()
    for row in rows:
        previous = AuditResult.model_validate_json(row[0])
        if not previous.is_demo and previous.scan_completeness == "COMPLETED":
            return previous
    return None
