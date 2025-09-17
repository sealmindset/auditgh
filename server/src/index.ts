import { createServer } from 'http';
import { createApp } from './app.js';
import { config } from './config/env.js';
import { logger } from './config/logging.js';

const app = createApp();
const server = createServer(app);

server.listen(config.port, () => {
  logger.info({ port: config.port }, 'Server listening');
});
