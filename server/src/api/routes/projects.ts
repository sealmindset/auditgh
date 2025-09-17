import { Router } from 'express';
import { requireAuth, requireRole } from '../../auth/middleware.js';
import { createProject, listProjects } from '../../db/repositories/projects.js';
import { createProjectSchema } from '../validators/projects.js';

export const projectsRouter = Router();

projectsRouter.get('/', requireAuth, async (_req, res, next) => {
  try {
    const data = await listProjects();
    res.json({ data });
  } catch (err) { next(err); }
});

projectsRouter.post('/', requireRole('project_admin'), async (req, res, next) => {
  try {
    const parsed = createProjectSchema.parse(req.body);
    const created = await createProject({
      ...parsed,
      created_by: req.session?.user?.id || null,
    });
    res.status(201).json({ data: created });
  } catch (err: any) {
    if (err?.name === 'ZodError') return res.status(422).json({ error: { code: 'validation_failed', issues: err.issues } });
    next(err);
  }
});
