import fs from 'fs'
import path from 'path'
import { pool } from '../db/pool.js'
import { logger } from '../config/logging.js'
import { config } from '../config/env.js'
import type { Scan } from '../db/repositories/scans.js'

export type BinariesRow = {
  project_id: string
  repo_short: string
  path: string
  filename: string
  extension: string
  size_bytes: number
  is_executable: boolean
  type: string
  sha256: string
  mode: string
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

export function parseBinariesDoc(doc: any, projectId: string, repoShort: string): BinariesRow[] {
  const out: BinariesRow[] = []
  const findings = (doc?.findings || []) as any[]
  for (const f of findings) {
    out.push({
      project_id: projectId,
      repo_short: repoShort,
      path: f?.path || '',
      filename: f?.filename || '',
      extension: f?.extension || '',
      size_bytes: typeof f?.size_bytes === 'number' ? f.size_bytes : Number(f?.size_bytes || 0),
      is_executable: !!f?.is_executable,
      type: f?.type || '',
      sha256: f?.sha256 || '',
      mode: f?.mode || '',
    })
  }
  return out
}

export async function bulkUpsertBinariesFindings(rows: BinariesRow[]): Promise<number> {
  if (!rows.length) return 0
  const cols = ['project_id','repo_short','path','filename','extension','size_bytes','is_executable','type','sha256','mode']
  const values: any[] = []
  const placeholders = rows.map((r, i) => {
    values.push(r.project_id, r.repo_short, r.path, r.filename, r.extension, r.size_bytes, r.is_executable, r.type, r.sha256, r.mode)
    const base = i * cols.length
    const ps = cols.map((_, j) => `$${base + j + 1}`).join(',')
    return `(${ps})`
  }).join(',')
  const sql = `insert into binaries_findings (${cols.join(',')}) values ${placeholders}
               on conflict (project_id, repo_short, path, sha256) do nothing`
  const res = await pool.query(sql, values)
  return res.rowCount ?? 0
}

export async function ingestBinariesFindings(scan: Scan): Promise<{ inserted: number, repos: string[] }> {
  const baseDir = path.resolve(config.auditWorkspaceDir, scan.id)
  let inserted = 0
  const touched = new Set<string>()
  const repos = enumerateRepoDirs(baseDir)

  for (const repoShortRaw of repos) {
    const repoDir = path.join(baseDir, repoShortRaw)
    const repoShort = repoShortRaw.toLowerCase()
    const jsonPath = path.join(repoDir, `${repoShortRaw}_binaries.json`)
    if (!fs.existsSync(jsonPath)) continue
    const doc = safeReadJson(jsonPath)
    if (!doc) continue
    try {
      const rows = parseBinariesDoc(doc, scan.project_id, repoShort)
      if (rows.length) {
        const n = await bulkUpsertBinariesFindings(rows)
        inserted += n
        touched.add(repoShort)
      }
    } catch (e) {
      logger.warn({ e, filePath: jsonPath, scanId: scan.id }, 'Binaries parse failed for file')
    }
  }

  logger.info({ scanId: scan.id, inserted, repos: Array.from(touched) }, 'Binaries ingest complete')
  return { inserted, repos: Array.from(touched) }
}

// Backfill from a mounted binaries_reports directory. Maps repo_short to projects by repo_url.
export async function backfillBinariesFromDir(baseDir: string, opts?: { projectId?: string, repoShort?: string }): Promise<{ inserted: number, repos: string[], skipped: string[] }> {
  const { projectId, repoShort } = opts || {}
  const dir = path.resolve(baseDir)
  if (!fs.existsSync(dir)) {
    logger.warn({ dir }, 'Binaries reports directory does not exist')
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
    const jsonPath = path.join(repoDir, `${name}_binaries.json`)
    if (!fs.existsSync(jsonPath)) { skipped.push(name); continue }
    const doc = safeReadJson(jsonPath)
    if (!doc) { skipped.push(name); continue }
    try {
      const rows = parseBinariesDoc(doc, pid, rs)
      if (rows.length) {
        const n = await bulkUpsertBinariesFindings(rows)
        inserted += n
        repos.push(name)
      } else {
        skipped.push(name)
      }
    } catch (e) {
      logger.warn({ e, repo: name }, 'Binaries backfill insert failed')
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
