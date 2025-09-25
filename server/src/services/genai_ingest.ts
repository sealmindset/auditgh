import fs from 'fs'
import path from 'path'
import { config } from '../config/env.js'
import { logger } from '../config/logging.js'

/** Shape produced by scan_genai_tokens.py artifact */
interface DetectedToken {
  provider: string
  token: string
  file_path?: string
  line_start?: number
  line_end?: number
  confidence?: 'low'|'medium'|'high'
  metadata?: Record<string, unknown>
  repo_short?: string
}

async function postJson(url: string, body: any): Promise<Response> {
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
  return res
}

function listRepoDirs(runDir: string): string[] {
  try {
    return fs.readdirSync(runDir, { withFileTypes: true })
      .filter(d => d.isDirectory() && d.name !== 'markdown')
      .map(d => d.name)
  } catch { return [] }
}

function readArtifact(repoDir: string, repoShort: string): DetectedToken[] {
  // Look for runs/<scanId>/<repo>/genai_tokens/<repo>_genai_tokens.json
  const dir = path.join(repoDir, 'genai_tokens')
  const file = path.join(dir, `${repoShort}_genai_tokens.json`)
  try {
    if (fs.existsSync(file)) {
      const raw = fs.readFileSync(file, 'utf-8')
      const arr = JSON.parse(raw)
      if (Array.isArray(arr)) return arr as DetectedToken[]
    }
  } catch {}
  return []
}

export async function ingestGenaiTokens(scan: { id: string, project_id: string }): Promise<{ inserted: number, repos: string[] }>{
  const baseDir = path.resolve(config.auditWorkspaceDir, scan.id)
  const repos = listRepoDirs(baseDir)
  const touched = new Set<string>()
  let inserted = 0

  const postgrest = process.env.POSTGREST_URL || 'http://postgrest:3000'

  // Resolve project api_id from uuid
  // We have only the uuid; query api.projects to get api_id
  let projectApiId: number | null = null
  try {
    const resp = await fetch(`${postgrest}/api/projects?select=id,uuid&uuid=eq.${scan.project_id}`)
    const json = await resp.json()
    if (Array.isArray(json) && json[0] && typeof json[0].id === 'number') {
      projectApiId = json[0].id
    }
  } catch (e) {
    logger.warn({ e }, 'Failed to resolve project api_id for genai ingestion')
  }
  if (!projectApiId) {
    logger.warn({ project_uuid: scan.project_id }, 'Skipping genai ingestion; unable to resolve project api_id')
    return { inserted: 0, repos: [] }
  }

  for (const repoShort of repos) {
    const repoDir = path.join(baseDir, repoShort)
    const items = readArtifact(repoDir, repoShort)
    if (!items.length) continue
    touched.add(repoShort)

    // Attach repo_short for each item
    const payload = items.map(it => ({
      provider: it.provider,
      token: it.token,
      file_path: it.file_path,
      line_start: it.line_start,
      line_end: it.line_end,
      confidence: it.confidence || 'medium',
      repo_short: repoShort,
      metadata: it.metadata || {}
    }))

    try {
      const resp = await postJson(`${postgrest}/rpc/upsert_ai_tokens`, { p_project_id: projectApiId, p_payload: payload })
      if (resp.status >= 400) {
        const txt = await resp.text()
        logger.warn({ status: resp.status, txt }, 'upsert_ai_tokens failed')
      } else {
        inserted += payload.length
      }
    } catch (e) {
      logger.warn({ e }, 'Failed posting upsert_ai_tokens')
    }
  }

  logger.info({ scanId: scan.id, inserted, repos: Array.from(touched) }, 'GenAI tokens ingest complete')
  return { inserted, repos: Array.from(touched) }
}
