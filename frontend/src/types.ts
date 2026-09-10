export type Status='CONFIRMED'|'LIKELY'|'REQUIRES_ACCESS'|'ASSET_RESIDUE'|'NOT_AFFECTED'|'HARDENING'
export interface Evidence{url:string;captured_at:string;evidence_type:string;excerpt:string;response_sha256:string;confidence:'high'|'medium'|'low';detection_method:string}
export interface Finding{is_demo:boolean;subject:string;status:Status;severity:string;version?:string;cve?:string;interpretation:string;business_risk:string;remediation:string;source?:string;access_required?:string;evidence:Evidence[]}
export interface ScoreFactor{subject:string;status:Status;points:number;reason:string}
export interface ScoreResult{value:number;formula:string;factors:ScoreFactor[];previous_comparison:null|number}
export interface AuditResult{is_demo:boolean;target:string;id:string;domain:string;started_at:string;completed_at:string;request_count:number;scope:string[];findings:Finding[];headers:Record<string,string>;cookies:Array<Record<string,string|boolean>>;report_sha256?:string;score?:ScoreResult}
export interface FindingChange{subject:string;cve?:string;previous_status?:Status;current_status?:Status;previous_version?:string;current_version?:string}
export interface AuditComparison{audit_id:string;previous_audit_id?:string;domain:string;available:boolean;score_delta?:number;added:FindingChange[];resolved:FindingChange[];changed:FindingChange[];unchanged_count:number}
