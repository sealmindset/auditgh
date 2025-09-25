import fs from 'fs'
import path from 'path'
import { pool } from '../db/pool.js'
import { logger } from '../config/logging.js'
import { config } from '../config/env.js'
import type { Scan } from '../db/repositories/scans.js'

export type TerraformRow = {
  project_id: string
  repo_short: string
  scanner: 'checkov' | 'trivy'
  rule_id: string
  rule_name?: string | null
  severity: 'critical'|'high'|'medium'|'low'|'unknown'
  resource?: string | null
  file_path: string
  line_start: number
  guideline_url?: string | null
}

function toSeverity(input: any): TerraformRow['severity'] {
  const s = String(input || '').trim().toLowerCase()
  if (s.startsWith('crit')) return 'critical'
  if (s.startsWith('hi')) return 'high'
  if (s.startsWith('med')) return 'medium'
  if (s.startsWith('lo')) return 'low'
  return 'unknown'
}

function safeReadJson(filePath: string): any | null {
  try {
    const raw = fs.readFileSync(filePath, 'utf-8')
    return JSON.parse(raw)
  } catch { return null }
}

function enumerateRepoDirs(scanDir: string): string[] {
  try {
    return fs.readdirSync(scanDir, { withFileTypes: true })
      .filter(d => d.isDirectory())
      .map(d => d.name)
  } catch { return [] }
}

function* enumerateCandidateFiles(repoDir: string, repoShort: string): Generator<{ path: string; kind: 'checkov'|'trivy' }> {
  const prefer = [
    { name: `${repoShort}_checkov.json`, kind: 'checkov' as const },
    { name: `${repoShort}_trivy_fs.json`, kind: 'trivy' as const },
  ]
  for (const p of prefer) {
    const f = path.join(repoDir, p.name)
    if (fs.existsSync(f)) yield { path: f, kind: p.kind }
  }
  // Fallback: scan directory for similar names
  try {
    const files = fs.readdirSync(repoDir)
    for (const f of files) {
      const lower = f.toLowerCase()
      if (lower.endsWith('_checkov.json')) yield { path: path.join(repoDir, f), kind: 'checkov' }
      if (lower.endsWith('_trivy_fs.json')) yield { path: path.join(repoDir, f), kind: 'trivy' }
    }
  } catch {}
}

export function parseCheckovDoc(doc: any, projectId: string, repoShort: string): TerraformRow[] {
  const out: TerraformRow[] = []
  const failed = (doc?.results?.failed_checks || []) as any[]
  for (const r of failed) {
    out.push({
      project_id: projectId,
      repo_short: repoShort,
      scanner: 'checkov',
      rule_id: r?.check_id || '',
      rule_name: r?.check_name || null,
      severity: toSeverity(r?.severity),
      resource: r?.resource || null,
      file_path: r?.repo_file_path || r?.file_path || r?.file_abs_path || '',
      line_start: Array.isArray(r?.file_line_range) ? Number(r.file_line_range[0]) : 0,
      guideline_url: r?.guideline || null,
    })
  }
  return out
}

export function parseTrivyDoc(doc: any, projectId: string, repoShort: string): TerraformRow[] {
  const out: TerraformRow[] = []
  const results = (doc?.Results || []) as any[]
  for (const res of results) {
    const target = res?.Target || ''
    const mis = (res?.Misconfigurations || []) as any[]
    for (const m of mis) {
      out.push({
        project_id: projectId,
        repo_short: repoShort,
        scanner: 'trivy',
        rule_id: m?.ID || '',
        rule_name: m?.Title || null,
        severity: toSeverity(m?.Severity),
        resource: m?.CauseMetadata?.Resource || null,
        file_path: target || '',
        line_start: typeof m?.CauseMetadata?.StartLine === 'number' ? Number(m.CauseMetadata.StartLine) : 0,
        guideline_url: m?.PrimaryURL || (Array.isArray(m?.References) && m.References.length > 0 ? m.References[0] : null),
      })
    }
  }
  return out
}

export async function bulkUpsertTerraformFindings(rows: TerraformRow[]): Promise<number> {
  if (!rows.length) return 0
  const cols = ['project_id','repo_short','scanner','rule_id','rule_name','severity','resource','file_path','line_start','guideline_url']
  const values: any[] = []
  const placeholders = rows.map((r, i) => {
    values.push(r.project_id, r.repo_short, r.scanner, r.rule_id, r.rule_name ?? null, r.severity, r.resource ?? null, r.file_path, r.line_start, r.guideline_url ?? null)
    const base = i * cols.length
    const ps = cols.map((_, j) => `$${base + j + 1}`).join(',')
    return `(${ps})`
  }).join(',')
  const sql = `insert into terraform_findings (${cols.join(',')}) values ${placeholders}
               on conflict (project_id, repo_short, scanner, rule_id, file_path, line_start) do nothing`
  const res = await pool.query(sql, values)
  return res.rowCount ?? 0
}

export async function ingestTerraformFindings(scan: Scan): Promise<{ inserted: number, repos: string[] }> {
  const baseDir = path.resolve(config.auditWorkspaceDir, scan.id)
  let inserted = 0
  const touched = new Set<string>()
  const repos = enumerateRepoDirs(baseDir)

  for (const repoShortRaw of repos) {
    const repoDir = path.join(baseDir, repoShortRaw)
    const repoShort = repoShortRaw.toLowerCase()
    const rows: TerraformRow[] = []
    for (const file of enumerateCandidateFiles(repoDir, repoShortRaw)) {
      const doc = safeReadJson(file.path)
      if (!doc) continue
      try {
        if (file.kind === 'checkov') rows.push(...parseCheckovDoc(doc, scan.project_id, repoShort))
        else if (file.kind === 'trivy') rows.push(...parseTrivyDoc(doc, scan.project_id, repoShort))
      } catch (e) {
        logger.warn({ e, filePath: file.path, scanId: scan.id }, 'Terraform parse failed for file')
      }
    }
    if (rows.length) {
      try {
        const n = await bulkUpsertTerraformFindings(rows)
        inserted += n
        touched.add(repoShort)
      } catch (e) {
        logger.warn({ e, scanId: scan.id, repo: repoShort }, 'Terraform ingest insert failed')
      }
    }
  }

  logger.info({ scanId: scan.id, inserted, repos: Array.from(touched) }, 'Terraform ingest complete')
  return { inserted, repos: Array.from(touched) }
}

// Backfill from a mounted terraform_reports directory. Maps repo_short to projects by repo_url.
export async function backfillTerraformFromDir(baseDir: string, opts?: { projectId?: string, repoShort?: string }): Promise<{ inserted: number, repos: string[], skipped: string[] }> {
  const { projectId, repoShort } = opts || {}
  const dir = path.resolve(baseDir)
  if (!fs.existsSync(dir)) {
    logger.warn({ dir }, 'Terraform reports directory does not exist')
    return { inserted: 0, repos: [], skipped: [] }
  }
  // Build repo_short -> project_id map
  type RowProj = { id: string, repo_url: string | null }
  const { rows: prows } = await pool.query<RowProj>('select id, repo_url from projects')
  const map = new Map<string, string>()
  for (const p of prows) {
    const rs = repoShortFromUrl(p.repo_url)
    if (rs) map.set(rs.toLowerCase(), p.id)
  }
  let inserted = 0
  const repos: string[] = []
  const skipped: string[] = []
  let entries: fs.Dirent[] = []
  try { entries = fs.readdirSync(dir, { withFileTypes: true }) } catch { entries = [] }
  for (const e of entries) {
    if (!e.isDirectory()) continue
    const name = e.name
    const rs = name.toLowerCase()
    if (repoShort && rs !== repoShort.toLowerCase()) continue
    const pid = projectId || map.get(rs)
    if (!pid) { skipped.push(name); continue }
    const repoDir = path.join(dir, name)
    const rows: TerraformRow[] = []
    // Prefer {repo}_checkov.json and {repo}_trivy_fs.json
    const candidates = [
      { p: path.join(repoDir, `${name}_checkov.json`), kind: 'checkov' as const },
      { p: path.join(repoDir, `${name}_trivy_fs.json`), kind: 'trivy' as const },
    ]
    for (const c of candidates) {
      if (!fs.existsSync(c.p)) continue
      const doc = safeReadJson(c.p)
      if (!doc) continue
      try {
        if (c.kind === 'checkov') rows.push(...parseCheckovDoc(doc, pid, rs))
        else rows.push(...parseTrivyDoc(doc, pid, rs))
      } catch (e) {
        logger.warn({ e, filePath: c.p }, 'Terraform backfill parse failed')
      }
    }
    if (rows.length) {
      try {
        const n = await bulkUpsertTerraformFindings(rows)
        inserted += n
        repos.push(name)
      } catch (e) {
        logger.warn({ e, repo: name }, 'Terraform backfill insert failed')
      }
    } else {
      skipped.push(name)
    }
  }
  return { inserted, repos, skipped }
}

function repoShortFromUrl(u: string | null): string | null {
  if (!u) return null
  try {
    if (/^git@/.test(u)) {
      const m = /^git@[^:]+:([^\s]+)$/.exec(u.trim())
      if (m) {
        const parts = m[1].replace(/\.git$/,'').split('/')
        return parts.length >= 2 ? parts[1] : parts[0]
      }
    }
    const url = new URL(u)
    const parts = url.pathname.replace(/^\//,'').replace(/\.git$/,'').split('/')
    return parts.length >= 2 ? parts[1] : parts[0]
  } catch { return null }
}
