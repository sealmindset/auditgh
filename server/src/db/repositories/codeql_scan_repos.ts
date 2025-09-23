import { pool } from '../../db/pool.js';

export type CodeqlScanRepo = {
  project_id: string;
  scan_id: string;
  repo_short: string;
  language?: string | null;
  has_sarif?: boolean;
  findings_count?: number;
};

export async function bulkUpsertScanRepos(rows: CodeqlScanRepo[]): Promise<number> {
  if (!rows.length) return 0;
  const cols = ['project_id','scan_id','repo_short','language','has_sarif','findings_count'];
  const values: any[] = [];
  const placeholders = rows.map((r, i) => {
    values.push(
      r.project_id,
      r.scan_id,
      r.repo_short,
      r.language ?? null,
      r.has_sarif ?? true,
      r.findings_count ?? 0,
    );
    const base = i * cols.length;
    const ps = cols.map((_, j) => `$${base + j + 1}`).join(',');
    return `(${ps})`;
  }).join(',');
  const sql = `insert into codeql_scan_repos (${cols.join(',')}) values ${placeholders}
               on conflict (scan_id, repo_short, language)
               do update set has_sarif = excluded.has_sarif,
                             findings_count = excluded.findings_count`;
  const res = await pool.query(sql, values);
  return res.rowCount ?? 0;
}
