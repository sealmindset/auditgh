import { Pool } from 'pg';
import { config } from '../config/env.js';
import { logger } from '../config/logging.js';

export const pool = new Pool({ connectionString: config.databaseUrl });

export async function pingDb(): Promise<boolean> {
  try {
    await pool.query('select 1');
    return true;
  } catch (err) {
    logger.error({ err }, 'DB ping failed');
    return false;
  }
}
