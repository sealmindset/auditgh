import express from 'express'
import { requireRole } from '../../auth/middleware.js'
import { backfillBinariesFromDir } from '../../services/binaries_ingest.js'

const router = express.Router()

// One-off backfill endpoint to import existing binaries_reports without re-running scans
// Requires super_admin by default. Optional query/body parameters:
// - baseDir: override base directory (default: /workspace/binaries_reports)
// - project_id: limit backfill to a single project UUID
// - repo_short: limit to a single repo short name (e.g., terraform-goof)
router.post('/backfill', requireRole('super_admin'), async (req, res) => {
  try {
    const baseDir = (req.body?.baseDir as string) || (req.query.baseDir as string) || '/workspace/binaries_reports'
    const projectId = (req.body?.project_id as string) || (req.query.project_id as string) || undefined
    const repoShort = (req.body?.repo_short as string) || (req.query.repo_short as string) || undefined
    const result = await backfillBinariesFromDir(baseDir, { projectId, repoShort })
    return res.json({ ok: true, ...result })
  } catch (e: any) {
    return res.status(500).json({ error: { code: 'binaries_backfill_failed', message: String(e?.message || e) } })
  }
})

export const binariesRouter = router
