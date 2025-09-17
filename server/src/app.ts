import express from 'express';
import cookieParser from 'cookie-parser';
import { httpLogger, logger } from './config/logging.js';
import { requestId } from './middleware/requestId.js';
import { applySecurity } from './config/security.js';
import { applySession } from './config/session.js';
import { healthRouter } from './api/routes/health.js';
import { authRouter } from './auth/routes.js';
import { attachDevBypass } from './auth/middleware.js';
import { projectsRouter } from './api/routes/projects.js';
import { errorHandler } from './middleware/errorHandler.js';

export function createApp() {
  const app = express();

  app.disable('x-powered-by');
  app.use(httpLogger);
  app.use(requestId);
  app.use(express.json({ limit: '1mb' }));
  app.use(express.urlencoded({ extended: false }));
  app.use(cookieParser());

  // Inject dev bypass user globally in dev mode
  app.use(attachDevBypass);

  applySession(app);
  applySecurity(app);

  app.use('/health', healthRouter);
  app.use('/auth', authRouter);
  app.use('/api/projects', projectsRouter);

  // Not found
  app.use((_: express.Request, res: express.Response) => {
    res.status(404).json({ error: { code: 'not_found', message: 'Not Found' } });
  });

  app.use(errorHandler);

  logger.info('App initialized');
  return app;
}
