import session from 'express-session';
import connectRedis from 'connect-redis';
import { createClient } from 'redis';
import type { Express } from 'express';
import { config } from './env.js';

export function applySession(app: Express) {
  let store: session.Store | undefined;

  if (config.redisUrl) {
    const redisClient = createClient({ url: config.redisUrl });
    const RedisStore = connectRedis(session);
    store = new RedisStore({ client: redisClient as any, prefix: 'sess:' });
    redisClient.on('error', (err) => console.error('Redis error', err));
    redisClient.connect().catch(() => {/* handled by health */});
  }

  app.use(session({
    name: 'sid',
    secret: config.sessionSecret,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: 'lax',
      secure: config.nodeEnv === 'production',
      maxAge: 7 * 24 * 60 * 60 * 1000,
    },
    store,
  }));
}
