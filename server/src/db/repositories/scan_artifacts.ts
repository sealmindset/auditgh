import { pool } from '../../db/pool.js';

export type ScanArtifact = {
  id: string;
  api_id: number;
  scan_id: string;
  name: string;
  path: string;
  mime: string | null;
  size_bytes: number | null;
  created_at: string;
  updated_at: string;
};

export async function createScanArtifact(input: { scan_id: string; name: string; path: string; mime?: string | null; size_bytes?: number | null; }): Promise<ScanArtifact> {
  const q = `insert into scan_artifacts (scan_id, name, path, mime, size_bytes)
             values ($1, $2, $3, $4, $5)
             returning *`;
  const params = [input.scan_id, input.name, input.path, input.mime || null, input.size_bytes ?? null];
  const { rows } = await pool.query<ScanArtifact>(q, params);
  return rows[0];
}
