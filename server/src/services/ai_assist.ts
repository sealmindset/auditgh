import { pool } from '../db/pool.js'
import { logger } from '../config/logging.js'
import { callOllamaChat, type ChatMessage as MsgO } from './ai_providers/ollama.js'
import { callOpenAIChat, type ChatMessage as MsgA } from './ai_providers/openai.js'
import { discoverForContext, credibleExploitFound, type DiscoveredRef } from './discovery.js'
import { normalizeFindingKey, upsertExploitStatus } from './exploitability.js'

export type AnalysisInput = {
  provider: 'ollama' | 'openai'
  model?: string
  target: 'terraform' | 'oss' | 'codeql' | 'secret' | 'cicd'
  projectId?: string
  repoShort?: string
  context: Record<string, any>
  referenceUrls?: string[]
  autoDiscovery?: boolean
  mode?: 'citations_only' | 'analysis_with_citations'
  discoveryMax?: number
  setExploitStatusFromCitations?: boolean
}

export async function fetchExtract(url: string): Promise<string> {
  try {
    const resp = await fetch(url, { method: 'GET' })
    const text = await resp.text()
    // naive html->text
    const noScripts = text.replace(/<script[\s\S]*?<\/script>/gi, ' ')
    const noStyles = noScripts.replace(/<style[\s\S]*?<\/style>/gi, ' ')
    const stripped = noStyles.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim()
    return stripped.slice(0, 4000)
  } catch (e) {
    logger.warn({ url, e }, 'fetchExtract failed')
    return ''
  }
}

function buildPrompt(input: AnalysisInput, referenceExtracts: string[]): { system: string, user: string } {
  const ctx = JSON.stringify(input.context, null, 2)
  const refs = (input.referenceUrls || []).map((u, i) => `Reference ${i+1}: ${u}\nExcerpt: ${(referenceExtracts[i] || '').slice(0, 1000)}`).join('\n\n')
  if ((input.mode || 'citations_only') === 'citations_only') {
    const system = 'You are a security citations assistant. Return only a list of authoritative citations that substantiate exploitability (e.g., PoC or public exploit). If none are credible, state "No credible PoC found". Do NOT provide how-to steps.'
    const user = `Target: ${input.target}\n\nContext JSON:\n${ctx}\n\n${refs ? `References:\n${refs}\n\n` : ''}Return citations only: one per line with a short justification.`
    return { system, user }
  }
  const system = 'You are an application security assistant. Provide practical guidance and cite sources. If uncertain, say so.'
  const ask = [
    'Tasks:',
    '1) Explain the risk and conditions required for exploitation.',
    '2) Recommend remediation with concrete code/config examples.',
    '3) Provide 3–5 authoritative references with links (e.g., Snyk, vendor advisories, NVD).',
  ].join('\n')
  const user = `Target: ${input.target}\n\nContext JSON:\n${ctx}\n\n${refs ? `References:\n${refs}\n\n` : ''}${ask}`
  return { system, user }
}


export async function performAnalysis(input: AnalysisInput): Promise<{ row: any }> {
  const autoDiscovery = input.autoDiscovery !== false
  const setExploitFromCitations = input.setExploitStatusFromCitations === true
  let referenceUrls = (input.referenceUrls || []).filter(Boolean)
  let discoveryRefs: DiscoveredRef[] = []
  let discoveryLogs: any[] = []
  if (autoDiscovery) {
    try {
      const { references, queries } = await discoverForContext({ target: input.target, context: input.context, max: input.discoveryMax || 10 })
      discoveryRefs = references
      discoveryLogs = queries
      referenceUrls = [...referenceUrls, ...references.map(r => r.url)]
    } catch (e) {
      logger.warn({ e: String(e) }, 'auto discovery failed')
    }
  }
  // Fetch extracts
  const extracts: string[] = []
  for (const u of referenceUrls) {
    const t = await fetchExtract(u)
    extracts.push(t)
  }
  const { system, user } = buildPrompt({ ...input, referenceUrls }, extracts)
  const messages: Array<MsgO | MsgA> = [
    { role: 'system', content: system },
    { role: 'user', content: user },
  ]
  let responseText = ''
  let durationMs = 0
  const started = Date.now()
  if (input.provider === 'ollama') {
    const { text, durationMs: d } = await callOllamaChat({ messages: messages as MsgO[], model: input.model })
    responseText = text
    durationMs = d
  } else {
    const { text, durationMs: d } = await callOpenAIChat({ messages: messages as MsgA[], model: input.model })
    responseText = text
    durationMs = d
  }
  const finished = Date.now()
  const totalMs = durationMs || (finished - started)

  const insertSql = `insert into public.ai_assist_analyses
    (project_id, repo_short, target, provider, model, prompt_text, request_context, reference_urls, reference_extracts, response_text, status, duration_ms, created_by)
    values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'completed',$11,$12)
    returning api_id as id, id as uuid, project_id, repo_short, target, provider, model, prompt_text, request_context, reference_urls, reference_extracts, response_text, status, duration_ms, created_at, created_by`
  const vals = [
    input.projectId || null,
    input.repoShort || null,
    input.target,
    input.provider,
    input.model || (input.provider === 'ollama' ? 'qwen2.5:3b' : 'gpt-4o-mini'),
    `${system}\n\n---\n\n${user}`,
    JSON.stringify({ ...(input.context || {}), discovery: { refs: discoveryRefs, logs: discoveryLogs } }),
    JSON.stringify(referenceUrls),
    JSON.stringify(extracts),
    responseText,
    totalMs,
    null,
  ]
  const { rows } = await pool.query(insertSql, vals)
  const row = rows?.[0] || null
  logger.info({ provider: input.provider, model: input.model, target: input.target, projectId: input.projectId, repo: input.repoShort, durationMs: totalMs }, 'AI Assist analysis complete')

  // Conditionally set exploit_available=true when substantiated
  try {
    if (setExploitFromCitations) {
      const key = normalizeFindingKey(input.target, input.context)
      if (key) {
        const credible = credibleExploitFound(discoveryRefs)
        if (credible) {
          await upsertExploitStatus(key.type, key.key, true, discoveryRefs, 'ai', false)
        }
      }
    }
  } catch (e) {
    logger.warn({ e: String(e) }, 'failed to upsert exploitability status')
  }
  return { row }
}
