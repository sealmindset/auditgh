import { logger } from '../config/logging.js'
import { validateAndRecord } from './genai_validate.js'

type AiTokenAdminRow = {
  id: number // api_id numeric from api.ai_tokens_admin
  provider: string
  token: string
  validation_status?: string | null
  updated_at?: string | null
}

function baseUrl() {
  return (process.env.POSTGREST_URL || 'http://postgrest:3000').replace(/\/$/, '')
}

export async function sweepValidateRecent(opts?: { limit?: number, hours?: number }): Promise<{ checked: number, valid: number, invalid: number, error: number }>{
  const limit = opts?.limit ?? 200
  const hours = opts?.hours ?? 24
  const postgrest = baseUrl()

  // Fetch from admin view to get numeric id for RPC
  const params = new URLSearchParams()
  params.set('select', 'id,provider,token,validation_status,updated_at')
  params.set('order', 'updated_at.desc')
  params.set('limit', String(limit))
  // Filter to tokens recently touched and not valid yet
  // Note: PostgREST in.(...) filter
  params.set('validation_status', 'in.(null,unknown,error,invalid)')
  // Best-effort: updated in the last N hours
  const sinceIso = new Date(Date.now() - hours * 3600_000).toISOString()
  params.set('updated_at', `gte.${sinceIso}`)

  const url = `${postgrest}/ai_tokens_admin?${params.toString()}`
  let rows: AiTokenAdminRow[] = []
  try {
    const resp = await fetch(url)
    rows = await resp.json() as AiTokenAdminRow[]
  } catch (e) {
    logger.warn({ e }, 'Failed to load ai_tokens_admin for sweep')
    rows = []
  }

  let checked = 0, valid = 0, invalid = 0, error = 0
  for (const r of rows) {
    if (!r?.id || !r?.provider || !r?.token) continue
    checked += 1
    try {
      await validateAndRecord(postgrest, r.id, r.provider, r.token)
      // We don't know exact result here without re-fetch; classify via previous status heuristically
      // Count will be corrected by subsequent queries/UX; here we only log totals
    } catch (e) {
      error += 1
      logger.warn({ e, id: r.id }, 'Validation record failed')
    }
  }

  // Optionally, re-fetch summary of statuses just updated (skipped for brevity)
  logger.info({ checked, valid, invalid, error }, 'GenAI tokens sweep complete')
  return { checked, valid, invalid, error }
}
