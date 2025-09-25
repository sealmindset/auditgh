import express from 'express'
import { requireRole } from '../../auth/middleware.js'

const router = express.Router()

function baseUrl() {
  return (process.env.POSTGREST_URL || 'http://postgrest:3000').replace(/\/$/, '')
}

router.get('/', async (req, res) => {
  try {
    const base = baseUrl()
    const params = new URLSearchParams()
    // Default select: do not include secret value (public view excludes it by design)
    params.set('select', (req.query.select as string) || 'project_name,repo_short,detector,rule_id,description,file_path,line_start,line_end,confidence,validation_status,created_at,updated_at,metadata')
    if (!req.query.order) params.set('order', 'created_at.desc')
    if (req.query.limit) params.set('limit', String(req.query.limit))
    if (req.query.project_name) params.set('project_name', `eq.${req.query.project_name}`)
    if (req.query.repo_short) params.set('repo_short', `eq.${req.query.repo_short}`)
    if (req.query.detector) params.set('detector', `eq.${req.query.detector}`)
    if (req.query.validation_status) params.set('validation_status', `eq.${req.query.validation_status}`)

    const url = `${base}/secret_leaks?${params.toString()}`
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

export const secretLeaksRouter = router

// Admin-only route that includes secret values via api.secret_leaks_admin
router.get('/admin', requireRole('super_admin'), async (req, res) => {
  try {
    const base = baseUrl()
    const params = new URLSearchParams()
    // Admin view can include secret column
    params.set('select', (req.query.select as string) || 'project_name,repo_short,detector,rule_id,description,secret,file_path,line_start,line_end,confidence,validation_status,created_at,updated_at,metadata')
    if (!req.query.order) params.set('order', 'created_at.desc')
    if (req.query.limit) params.set('limit', String(req.query.limit))
    if (req.query.project_name) params.set('project_name', `eq.${req.query.project_name}`)
    if (req.query.repo_short) params.set('repo_short', `eq.${req.query.repo_short}`)
    if (req.query.detector) params.set('detector', `eq.${req.query.detector}`)
    if (req.query.validation_status) params.set('validation_status', `eq.${req.query.validation_status}`)

    const url = `${base}/secret_leaks_admin?${params.toString()}`
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
