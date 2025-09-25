import fs from 'fs'
import type { Dirent } from 'fs'
import path from 'path'
import { config } from '../config/env.js'
import { logger } from '../config/logging.js'

type Detector = 'gitleaks' | 'trufflehog'

type RawRecord = Record<string, any> | null | undefined

type SecretPayload = {
  detector: Detector | 'other'
  repo_short: string
  rule_id: string | null
  description: string | null
  secret: string
  file_path: string | null
  line_start: number | null
  line_end: number | null
  confidence: 'low' | 'medium' | 'high'
  validation_status: string
  metadata: Record<string, any>
}

function listRepoDirs(runDir: string): string[] {
  try {
    return (fs.readdirSync(runDir, { withFileTypes: true }) as Dirent[])
      .filter((d: Dirent) => d.isDirectory() && d.name !== 'markdown')
      .map((d: Dirent) => d.name)
  } catch { return [] }
}

function safeReadJson(filePath: string): RawRecord {
  try {
    const raw = fs.readFileSync(filePath, 'utf-8')
    const parsed = JSON.parse(raw)
    return parsed
  } catch {
    return null
  }
}

function toInt(value: any): number | null {
  if (value == null) return null
  const n = Number(value)
  return Number.isFinite(n) ? n : null
}

function mapGitleaksRecord(record: any, repoShort: string): SecretPayload | null {
  if (!record) return null
  const secret = typeof record.Secret === 'string' ? record.Secret : (typeof record.secret === 'string' ? record.secret : null)
  if (!secret) return null
  const desc = record.Description || record.description || null
  const filePath = record.File || record.file || null
  const startLine = toInt(record.StartLine ?? record.startLine)
  const endLine = toInt(record.EndLine ?? record.endLine)
  const ruleId = record.RuleID || record.ruleId || record.rule_id || null
  const entropy = typeof record.Entropy === 'number' ? record.Entropy : (typeof record.entropy === 'number' ? record.entropy : null)
  let confidence: 'low' | 'medium' | 'high' = 'medium'
  if (entropy != null) {
    confidence = entropy >= 5.0 ? 'high' : entropy >= 3.5 ? 'medium' : 'low'
  }
  return {
    detector: 'gitleaks',
    repo_short: repoShort,
    rule_id: ruleId ? String(ruleId) : null,
    description: desc ? String(desc) : null,
    secret,
    file_path: filePath ? String(filePath) : null,
    line_start: startLine,
    line_end: endLine,
    confidence,
    validation_status: 'unknown',
    metadata: {
      match: record.Match || record.match || null,
      entropy,
      fingerprint: record.Fingerprint || record.fingerprint || null,
      commit: record.Commit || record.commit || null,
      author: record.Author || record.author || null,
      email: record.Email || record.email || null,
      date: record.Date || record.date || null,
      tags: record.Tags || record.tags || null,
    },
  }
}

function mapTrufflehogRecord(record: any, repoShort: string): SecretPayload | null {
  if (!record) return null
  // TruffleHog V3 JSON emits findings with "DetectorType", "Raw", "Redacted", etc.
  const secret = typeof record.Raw === 'string' ? record.Raw : (typeof record.raw === 'string' ? record.raw : null)
  if (!secret) return null
  const desc = record.Description || record.description || null
  const filePath = record.SourceMetadata?.Data?.Filesystem?.file || record.SourceMetadata?.filesystem?.file || record.File || record.file || null
  const startLine = toInt(record.SourceMetadata?.Data?.Filesystem?.line || record.line || record.StartLine)
  const detectorName = record.DetectorName || record.Detector || record.detector || null
  const detectorType = record.DetectorType || record.detectorType || null
  const ruleId = record.RuleID || record.rule_id || detectorName || detectorType || null
  const matches: any[] = Array.isArray(record.RawBytes) ? record.RawBytes : []
  let confidence: 'low' | 'medium' | 'high' = 'medium'
  const severity = (record.Severity || record.severity || '').toString().toLowerCase()
  if (severity === 'high' || severity === 'critical') confidence = 'high'
  else if (severity === 'low') confidence = 'low'
  return {
    detector: 'trufflehog',
    repo_short: repoShort,
    rule_id: ruleId ? String(ruleId) : null,
    description: desc ? String(desc) : null,
    secret,
    file_path: filePath ? String(filePath) : null,
    line_start: startLine,
    line_end: startLine,
    confidence,
    validation_status: 'unknown',
    metadata: {
      detector_name: detectorName,
      detector_type: detectorType,
      redacted: record.Redacted || record.redacted || null,
      findings: matches?.length ? matches : undefined,
      source_metadata: record.SourceMetadata || record.source_metadata || null,
      extra: record.ExtraData || record.extra || null,
    },
  }
}

function collectSecretsFromRepo(baseDir: string, repoShort: string): SecretPayload[] {
  const repoDir = path.join(baseDir, repoShort)
  let files: string[] = []
  try {
    files = fs.readdirSync(repoDir)
  } catch {
    return []
  }
  const payload: SecretPayload[] = []
  for (const file of files) {
    const lower = file.toLowerCase()
    const fullPath = path.join(repoDir, file)
    if (lower.endsWith('_gitleaks.json')) {
      const data = safeReadJson(fullPath)
      if (Array.isArray(data)) {
        for (const rec of data) {
          const mapped = mapGitleaksRecord(rec, repoShort)
          if (mapped) payload.push(mapped)
        }
      }
    } else if (lower.endsWith('_trufflehog.json')) {
      const data = safeReadJson(fullPath)
      if (Array.isArray(data)) {
        for (const rec of data) {
          const mapped = mapTrufflehogRecord(rec, repoShort)
          if (mapped) payload.push(mapped)
        }
      }
    }
  }
  return payload
}

async function resolveProjectApiId(postgrest: string, projectUuid: string): Promise<number | null> {
  try {
    const resp = await fetch(`${postgrest}/api/projects?select=id,uuid&uuid=eq.${projectUuid}`)
    if (!resp.ok) return null
    const data = await resp.json()
    const row = Array.isArray(data) ? data[0] : null
    if (row && typeof row.id === 'number') {
      return row.id
    }
  } catch (e) {
    logger.warn({ e, projectUuid }, 'Failed to resolve project api_id for secret leak ingestion')
  }
  return null
}

async function postUpsert(postgrest: string, projectApiId: number, items: SecretPayload[]): Promise<number> {
  if (!items.length) return 0
  try {
    const resp = await fetch(`${postgrest}/rpc/upsert_secret_leaks`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        p_project_id: projectApiId,
        p_payload: items.map(it => ({
          detector: it.detector,
          repo_short: it.repo_short,
          rule_id: it.rule_id,
          description: it.description,
          secret: it.secret,
          file_path: it.file_path,
          line_start: it.line_start,
          line_end: it.line_end,
          confidence: it.confidence,
          validation_status: it.validation_status,
          metadata: it.metadata,
        })),
      }),
    })
    if (!resp.ok) {
      const txt = await resp.text()
      logger.warn({ status: resp.status, txt }, 'upsert_secret_leaks failed')
      return 0
    }
    const inserted = await resp.json().catch(() => null)
    return typeof inserted === 'number' ? inserted : items.length
  } catch (e) {
    logger.warn({ e }, 'Failed posting upsert_secret_leaks')
    return 0
  }
}

export async function ingestSecretLeaks(scan: { id: string, project_id: string }): Promise<{ inserted: number, repos: string[] }> {
  const baseDir = path.resolve(config.auditWorkspaceDir, scan.id)
  const repos = listRepoDirs(baseDir)
  const touched = new Set<string>()
  let inserted = 0

  const postgrest = (process.env.POSTGREST_URL || 'http://postgrest:3000').replace(/\/$/, '')
  const projectApiId = await resolveProjectApiId(postgrest, scan.project_id)
  if (!projectApiId) {
    logger.warn({ project_uuid: scan.project_id }, 'Skipping secret leak ingestion; unable to resolve project api_id')
    return { inserted: 0, repos: [] }
  }

  for (const repoShort of repos) {
    const items = collectSecretsFromRepo(baseDir, repoShort)
    if (!items.length) continue
    touched.add(repoShort)
    const count = await postUpsert(postgrest, projectApiId, items)
    inserted += count
  }

  logger.info({ scanId: scan.id, inserted, repos: Array.from(touched) }, 'Secret leak ingest complete')
  return { inserted, repos: Array.from(touched) }
}
