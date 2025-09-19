import { pool } from '../../db/pool.js';

export type Finding = {
  id: string;
  api_id: number;
  project_id: string;
  scan_id: string | null;
  source: 'gitleaks'|'codeql'|'oss'|'terraform'|'cicd'|'binaries'|'linecount'|'custom';
  rule_id: string | null;
  title: string;
  description: string | null;
  severity: 'critical'|'high'|'medium'|'low'|'info';
  status: 'open'|'triaged'|'accepted'|'risk_accepted'|'remediated'|'duplicate'|'false_positive';
  location: any;
  cwe: string | null;
  kev_id: string | null;
  epss_score: number | null;
  tags: string[] | null;
  metadata: any;
  created_at: string;
  updated_at: string;
};

export async function createFinding(input: {
  project_id: string;
  scan_id?: string | null;
  source?: Finding['source'];
  rule_id?: string | null;
  title: string;
  description?: string | null;
  severity?: Finding['severity'];
  status?: Finding['status'];
  location?: any;
  cwe?: string | null;
  kev_id?: string | null;
  epss_score?: number | null;
  tags?: string[] | null;
  metadata?: any;
}): Promise<Finding> {
  const q = `insert into findings 
    (project_id, scan_id, source, rule_id, title, description, severity, status, location, cwe, kev_id, epss_score, tags, metadata)
    values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
    returning *`;
  const params = [
    input.project_id,
    input.scan_id ?? null,
    input.source ?? 'custom',
    input.rule_id ?? null,
    input.title,
    input.description ?? null,
    input.severity ?? 'info',
    input.status ?? 'open',
    input.location ?? null,
    input.cwe ?? null,
    input.kev_id ?? null,
    input.epss_score ?? null,
    input.tags ?? null,
    input.metadata ?? {},
  ];
  const { rows } = await pool.query<Finding>(q, params);
  return rows[0];
}
