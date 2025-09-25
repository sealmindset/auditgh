import express from 'express'
import { sweepValidateRecent } from '../../services/genai_sweep.js'

const router = express.Router()

function baseUrl() {
  return (process.env.POSTGREST_URL || 'http://postgrest:3000').replace(/\/$/, '')
}

router.get('/', async (req, res) => {
  try {
    const base = baseUrl()
    // Allow simple passthrough filters
    const params = new URLSearchParams()
    // select and order defaults
    params.set('select', (req.query.select as string) || 'project_name,provider,token,repo_short,validation_status,file_path,line_start,line_end,created_at,updated_at')
    if (!req.query.order) params.set('order', 'created_at.desc')
    if (req.query.limit) params.set('limit', String(req.query.limit))
    if (req.query.provider) params.set('provider', `eq.${req.query.provider}`)
    if (req.query.repo_short) params.set('repo_short', `eq.${req.query.repo_short}`)
    if (req.query.validation_status) params.set('validation_status', `eq.${req.query.validation_status}`)

    const url = `${base}/ai_tokens?${params.toString()}`
    const resp = await fetch(url)
    const txt = await resp.text()
    if (resp.status >= 400) {
      return res.status(resp.status).json({ error: { code: 'postgrest_error', message: txt } })
    }
    let data: any
    try { data = txt ? JSON.parse(txt) : [] } catch { data = [] }
    return res.json({ items: data })
  } catch (e: any) {
    return res.status(500).json({ error: { code: 'proxy_error', message: String(e?.message || e) } })
  }
})

export const aiTokensRouter = router

router.post('/sweep', async (req, res) => {
  try {
    const limit = typeof req.body?.limit === 'number' ? req.body.limit : undefined
    const hours = typeof req.body?.hours === 'number' ? req.body.hours : undefined
    const result = await sweepValidateRecent({ limit, hours })
    return res.json({ ok: true, data: result })
  } catch (e: any) {
    return res.status(500).json({ error: { code: 'sweep_error', message: String(e?.message || e) } })
  }
})
