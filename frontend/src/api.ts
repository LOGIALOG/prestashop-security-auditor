import type {AuditComparison,AuditResult} from './types'
const API='http://127.0.0.1:8000/api'
export async function runAudit(payload:{target:string;authorization_confirmed:boolean;max_requests:number;delay_seconds:number}):Promise<AuditResult>{const response=await fetch(`${API}/audits`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});if(!response.ok)throw new Error((await response.json()).detail||'Audit impossible');return response.json()}
export async function loadDemo():Promise<AuditResult>{const response=await fetch(`${API}/demo`);if(!response.ok)throw new Error('Mode démonstration indisponible');return response.json()}
export const reportUrl=(id:string)=>`${API}/audits/${id}/report`
export const demoReportUrl=()=>`${API}/demo/report`
export const jsonExportUrl=(audit:AuditResult)=>audit.is_demo?`${API}/demo/export.json`:`${API}/audits/${audit.id}/export.json`
export const sarifExportUrl=(audit:AuditResult)=>audit.is_demo?`${API}/demo/export.sarif`:`${API}/audits/${audit.id}/export.sarif`
export async function loadComparison(id:string):Promise<AuditComparison>{const response=await fetch(`${API}/audits/${id}/comparison`);if(!response.ok)throw new Error('Comparaison indisponible');return response.json()}
