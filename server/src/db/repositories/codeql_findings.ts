import { pool } from '../../db/pool.js';

export type CodeqlFinding = {
  project_id: string;
  scan_id: string;
  repo_short: string;
  language?: string | null;
  rule_id: string;
  rule_name?: string | null;
  severity: string;
  file: string;
  line: number;
  message: string;
  help_uri?: string | null;
  unique_key: string;
};

export async function bulkInsertFindings(rows: CodeqlFinding[]): Promise<number> {
  if (!rows.length) return 0;
  const cols = ['project_id','scan_id','repo_short','language','rule_id','rule_name','severity','file','line','message','help_uri','unique_key'];
  const values: any[] = [];
  const placeholders = rows.map((r, i) => {
    values.push(r.project_id, r.scan_id, r.repo_short, r.language ?? null, r.rule_id, r.rule_name ?? null, r.severity, r.file, r.line, r.message, r.help_uri ?? null, r.unique_key);
    const base = i*cols.length;
    const ps = cols.map((_, j) => `$${base + j + 1}`).join(',');
    return `(${ps})`;
  }).join(',');
  const sql = `insert into codeql_findings (${cols.join(',')}) values ${placeholders} on conflict (unique_key) do nothing`;
  const res = await pool.query(sql, values);
  // rowCount is not reliable for ON CONFLICT DO NOTHING; perform a count by unique_keys inserted could be expensive; return 0/rows.length best effort
  return res.rowCount ?? 0;
}

export async function listFindingsByScanRepo(args: { scan_id: string; repo_short: string; limit?: number; offset?: number; sort?: 'severity'|'rule'|'file'|'line'; dir?: 'asc'|'desc'; search?: string; severity?: string[]; }) {
  const limit = Math.min(args.limit ?? 50, 200);
  const offset = args.offset ?? 0;
  const dir = (args.dir === 'asc' ? 'asc' : 'desc');
  const sort = (args.sort || 'severity');
  const sortExpr = sort === 'rule' ? 'rule_id' : sort === 'file' ? 'file' : sort === 'line' ? 'line' : 'severity';
  const params: any[] = [args.scan_id, args.repo_short];
  let where = 'scan_id = $1 and repo_short = $2';
  if (args.search) {
    params.push(`%${args.search.toLowerCase()}%`);
    where += ` and (lower(rule_id) like $${params.length} or lower(message) like $${params.length} or lower(file) like $${params.length})`;
  }
  if (args.severity && args.severity.length) {
    params.push(args.severity);
    where += ` and lower(severity) = any($${params.length})`;
  }
  const totalSql = `select count(*)::int as cnt from codeql_findings where ${where}`;
  const { rows: trows } = await pool.query<{cnt:number}>(totalSql, params);
  const total = trows[0]?.cnt || 0;
  const dataSql = `select project_id, scan_id, repo_short, language, rule_id, rule_name, severity, file, line, message, help_uri
                   from codeql_findings where ${where}
                   order by ${sortExpr} ${dir}, created_at desc
                   limit ${limit} offset ${offset}`;
  const { rows } = await pool.query(dataSql, params);
  return { items: rows, total };
}

export async function listFindingsByProjectLatest(args: { project_id: string; repo_short: string; limit?: number; offset?: number; sort?: 'severity'|'rule'|'file'|'line'; dir?: 'asc'|'desc'; search?: string; severity?: string[]; }) {
  // Find latest scan_id for which we have any findings for this project+repo
  const q = `select scan_id, max(created_at) as max_created
             from codeql_findings where project_id = $1 and repo_short = $2
             group by scan_id order by max_created desc limit 1`;
  const { rows: head } = await pool.query<{scan_id:string}>(q, [args.project_id, args.repo_short]);
  if (!head.length) return { items: [], total: 0 };
  return listFindingsByScanRepo({ ...args, scan_id: head[0].scan_id });
}
