import fs from 'fs'
import path from 'path'
import { logger } from '../config/logging.js'
import { config } from '../config/env.js'
import type { Scan } from '../db/repositories/scans.js'
import { createFinding } from '../db/repositories/findings.js'

function toSeverity(input: any): 'critical'|'high'|'medium'|'low'|'info' {
  const s = String(input || '').toLowerCase()
  if (s === 'critical') return 'critical'
  if (s === 'high') return 'high'
  if (s === 'moderate' || s === 'medium') return 'medium'
  if (s === 'low') return 'low'
  // cvss numeric fallback
  const n = typeof input === 'number' ? input : Number.isFinite(parseFloat(s)) ? parseFloat(s) : NaN
  if (!Number.isNaN(n)) {
    if (n >= 9.0) return 'critical'
    if (n >= 7.0) return 'high'
    if (n >= 4.0) return 'medium'
    if (n > 0) return 'low'
  }
  return 'info'
}

function safeReadJson(filePath: string): any | null {
  try {
    const raw = fs.readFileSync(filePath, 'utf-8')
    return JSON.parse(raw)
  } catch { return null }
}

function parseMarkdownTable(mdPath: string) {
  try {
    const txt = fs.readFileSync(mdPath, 'utf-8')
    const lines = txt.split(/\r?\n/)
    const headerIdx = lines.findIndex(l => /\|\s*Severity\s*\|/i.test(l))
    const sepIdx = headerIdx >= 0 ? headerIdx + 1 : -1
    if (headerIdx < 0 || sepIdx < 0) return [] as any[]
    const items: any[] = []
    for (let i = sepIdx + 1; i < lines.length; i++) {
      const row = lines[i].trim()
      if (!row.startsWith('|')) break
      const cols = row.split('|').map(c => c.trim())
      // Try to infer minimal columns: | Severity | Package | Version | Advisory |
      const severity = (cols[1] || '').toLowerCase()
      const pkg = cols[2] || ''
      const version = cols[3] || ''
      const advisory = cols[4] || ''
      if (!severity && !pkg && !advisory) continue
      items.push({ severity, package: pkg, version, advisory_id: advisory })
    }
    return items
  } catch { return [] as any[] }
}

function enumerateRepoDirs(scanDir: string): string[] {
  try {
    return fs.readdirSync(scanDir, { withFileTypes: true })
      .filter(d => d.isDirectory())
      .map(d => d.name)
  } catch { return [] }
}

function* enumerateCandidateFiles(repoDir: string, repoShort: string): Generator<string> {
  // Prefer explicit patterns
  const prefer = [
    `${repoShort}_oss.json`,
    `${repoShort}_oss.md`,
    `oss.json`,
    `oss.md`,
    `npm-audit.json`,
    `pnpm-audit.json`,
    `yarn-audit.json`,
  ]
  for (const p of prefer) {
    const f = path.join(repoDir, p)
    if (fs.existsSync(f)) yield f
  }
  // Fallback: any small JSON/MD file that includes 'oss' in its name
  try {
    const files = fs.readdirSync(repoDir)
    for (const f of files) {
      const lower = f.toLowerCase()
      if ((lower.endsWith('.json') || lower.endsWith('.md')) && lower.includes('oss')) {
        yield path.join(repoDir, f)
      }
    }
  } catch {}
}

export async function ingestOssFindings(scan: Scan): Promise<{ inserted: number, repos: string[] }> {
  const baseDir = path.resolve(config.auditWorkspaceDir, scan.id)
  const repos = enumerateRepoDirs(baseDir)
  let inserted = 0
  const touched = new Set<string>()

  for (const repoShortRaw of repos) {
    const repoShort = repoShortRaw.toLowerCase()
    const repoDir = path.join(baseDir, repoShortRaw)
    let foundAny = false

    for (const filePath of enumerateCandidateFiles(repoDir, repoShortRaw)) {
      try {
        let items: any[] = []
        if (filePath.toLowerCase().endsWith('.json')) {
          const doc = safeReadJson(filePath)
          if (!doc) continue
          // Try common shapes
          if (Array.isArray(doc.vulnerabilities)) {
            items = doc.vulnerabilities
              .map((v: any) => ({
                severity: toSeverity(v.severity || v.cvss?.score || v.cvssScore),
                rule_id: v.id || v.advisoryId || v.osvId || v.cve || null,
                title: v.title || v.summary || v.module || v.package || 'OSS vulnerability',
                ecosystem: v.ecosystem || v.packageManager || 'npm',
                package: v.module || v.package || v.name || '',
                version: v.version || v.installedVersion || '',
                raw: undefined,
              }))
          } else if (doc.advisories && typeof doc.advisories === 'object') {
            items = Object.values(doc.advisories).map((v: any) => ({
              severity: toSeverity(v.severity),
              rule_id: v.id || v.github_advisory_id || v.cve || null,
              title: v.title || 'OSS advisory',
              ecosystem: 'npm',
              package: v.module_name || '',
              version: v.findings?.[0]?.version || v.vulnerable_versions || '',
              raw: undefined,
            }))
          } else if (Array.isArray(doc.results)) {
            items = doc.results.map((r: any) => ({
              severity: toSeverity(r.severity || r.cvss?.score),
              rule_id: r.id || r.advisory || null,
              title: r.title || 'OSS vulnerability',
              ecosystem: r.ecosystem || 'npm',
              package: r.package || '',
              version: r.version || '',
              raw: undefined,
            }))
          } else if (Array.isArray(doc)) {
            items = (doc as any[]).map((r: any) => ({
              severity: toSeverity(r.severity || r.cvss?.score),
              rule_id: r.id || r.advisory || null,
              title: r.title || 'OSS vulnerability',
              ecosystem: r.ecosystem || 'npm',
              package: r.package || r.name || '',
              version: r.version || '',
              raw: undefined,
            }))
          }
        } else if (filePath.toLowerCase().endsWith('.md')) {
          items = parseMarkdownTable(filePath)
        }

        for (const it of items) {
          foundAny = true
          touched.add(repoShort)
          const severity = toSeverity(it.severity)
          const title = String(it.title || `${it.package || ''} ${it.rule_id || ''}` || 'OSS vulnerability').trim()
          await createFinding({
            project_id: scan.project_id,
            scan_id: scan.id,
            source: 'oss',
            rule_id: it.rule_id ? String(it.rule_id) : null,
            title,
            severity,
            location: it.package || it.version ? { package: it.package || null, version: it.version || null } : null,
            tags: ['oss', (it.ecosystem || 'npm')],
            metadata: {
              repo_short: repoShort,
              ecosystem: it.ecosystem || 'npm',
              package: it.package || null,
              version: it.version || null,
              advisory_id: it.rule_id || null,
            },
          })
          inserted++
        }
      } catch (e) {
        logger.warn({ e, filePath, scanId: scan.id }, 'OSS ingest failed for file')
      }
    }

    if (!foundAny) {
      // No OSS artifacts detected for this repo; not an error.
    }
  }

  logger.info({ scanId: scan.id, inserted, repos: Array.from(touched) }, 'OSS ingest complete')
  return { inserted, repos: Array.from(touched) }
}
