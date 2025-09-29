import express from 'express'
import { performAnalysis } from '../../services/ai_assist.js'

const router = express.Router()

router.get('/providers', async (_req, res) => {
  return res.json({
    providers: [
      { key: 'ollama', models: [process.env.AI_ASSIST_DEFAULT_MODEL_OLLAMA || 'qwen2.5:3b'] },
      { key: 'openai', models: [process.env.AI_ASSIST_DEFAULT_MODEL_OPENAI || 'gpt-4o-mini'] },
    ],
    defaults: {
      provider: process.env.AI_ASSIST_DEFAULT_PROVIDER || 'ollama',
      ollamaModel: process.env.AI_ASSIST_DEFAULT_MODEL_OLLAMA || 'qwen2.5:3b',
      openaiModel: process.env.AI_ASSIST_DEFAULT_MODEL_OPENAI || 'gpt-4o-mini',
    },
  })
})

router.post('/assist', async (req, res) => {
  try {
    const provider = (req.body?.provider as string) || (process.env.AI_ASSIST_DEFAULT_PROVIDER || 'ollama')
    const model = (req.body?.model as string | undefined)
    const target = (req.body?.target as string)
    const projectId = (req.body?.project_id as string | undefined)
    const repoShort = (req.body?.repo_short as string | undefined)
    const context = (req.body?.context as Record<string, any>) || {}
    const referenceUrls = Array.isArray(req.body?.reference_urls) ? (req.body.reference_urls as string[]) : []
    const autoDiscovery = req.body?.auto_discovery !== false
    const mode = (req.body?.mode as 'citations_only'|'analysis_with_citations'|undefined) || 'citations_only'
    const discoveryMax = typeof req.body?.discovery_max === 'number' ? req.body.discovery_max : undefined
    const setExploitFromCitations = req.body?.set_exploit_from_citations === true

    if (!target) return res.status(400).json({ error: { code: 'bad_request', message: 'target is required' } })
    if (provider !== 'ollama' && provider !== 'openai') return res.status(400).json({ error: { code: 'bad_request', message: 'unsupported provider' } })

    const { row } = await performAnalysis({
      provider,
      model,
      target: target as any,
      projectId,
      repoShort,
      context,
      referenceUrls,
      autoDiscovery,
      mode,
      discoveryMax,
      setExploitStatusFromCitations: setExploitFromCitations,
    })
    return res.json({ ok: true, data: row })
  } catch (e: any) {
    return res.status(500).json({ error: { code: 'ai_assist_error', message: String(e?.message || e) } })
  }
})

export const aiAssistRouter = router
