import { pool } from '../../db/pool.js';
import type { QueryResult } from 'pg';

export type Project = {
  id: string; // uuid
  api_id: number;
  name: string;
  repo_url: string | null;
  description: string | null;
  is_active: boolean;
  created_at: string;
  updated_at: string;
};

export async function listProjects(): Promise<Project[]> {
  const { rows } = await pool.query<Project>('select * from projects order by created_at desc');
  return rows;
}

export async function createProject(input: { name: string; repo_url: string | null; description: string | null; created_by?: string | null; }): Promise<Project> {
  const q = `insert into projects (name, repo_url, description, created_by)
             values ($1, $2, $3, $4)
             returning *`;
  const params = [input.name, input.repo_url, input.description, input.created_by || null];
  const { rows } = await pool.query<Project>(q, params);
  return rows[0];
}
