import { pool } from '../../db/pool.js';

export type Scan = {
  id: string; // uuid
  api_id: number;
  project_id: string; // uuid
  profile: string | null;
  status: 'queued'|'running'|'success'|'failed'|'canceled';
  started_at: string | null;
  finished_at: string | null;
  summary_md_path: string | null;
  created_at: string;
  updated_at: string;
};

export async function createScan(input: { project_id: string; profile?: string | null; }): Promise<Scan> {
  const q = `insert into scans (project_id, profile, status)
             values ($1, $2, 'queued')
             returning *`;
  const params = [input.project_id, input.profile || null];
  const { rows } = await pool.query<Scan>(q, params);
  return rows[0];
}

export async function updateScanStatus(id: string, status: Scan['status'], args?: { started_at?: Date | null; finished_at?: Date | null; summary_md_path?: string | null; }): Promise<Scan | null> {
  const q = `update scans
             set status = coalesce($2, status),
                 started_at = coalesce($3, started_at),
                 finished_at = coalesce($4, finished_at),
                 summary_md_path = coalesce($5, summary_md_path),
                 updated_at = now()
             where id = $1
             returning *`;
  const params = [id, status, args?.started_at || null, args?.finished_at || null, args?.summary_md_path || null];
  const { rows } = await pool.query<Scan>(q, params);
  return rows[0] || null;
}

export async function getScan(id: string): Promise<Scan | null> {
  const { rows } = await pool.query<Scan>('select * from scans where id = $1', [id]);
  return rows[0] || null;
}

export async function listRecentScans(limit = 50): Promise<Scan[]> {
  const { rows } = await pool.query<Scan>('select * from scans order by created_at desc limit $1', [limit]);
  return rows;
}

export async function getLatestScanByProject(projectId: string): Promise<Scan | null> {
  const q = `select * from scans
             where project_id = $1 and status = 'success'
             order by created_at desc
             limit 1`;
  const { rows } = await pool.query<Scan>(q, [projectId]);
  return rows[0] || null;
}

export async function listRecentScansByProject(projectId: string, limit = 10): Promise<Scan[]> {
  const q = `select * from scans
             where project_id = $1
             order by created_at desc
             limit $2`;
  const { rows } = await pool.query<Scan>(q, [projectId, limit]);
  return rows;
}
