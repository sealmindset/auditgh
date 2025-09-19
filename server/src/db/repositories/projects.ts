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
  const { rows } = await pool.query<Project>('select * from projects order by name asc');
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

export async function getProject(id: string): Promise<Project | null> {
  const { rows } = await pool.query<Project>('select * from projects where id = $1', [id]);
  return rows[0] || null;
}

export async function updateProject(id: string, input: Partial<Pick<Project, 'name' | 'repo_url' | 'description' | 'is_active'>>): Promise<Project | null> {
  const fields: string[] = [];
  const values: any[] = [];
  let idx = 1;
  for (const [k, v] of Object.entries(input)) {
    fields.push(`${k} = $${idx++}`);
    values.push(v);
  }
  if (fields.length === 0) return getProject(id);
  values.push(id);
  const q = `update projects set ${fields.join(', ')}, updated_at = now() where id = $${idx} returning *`;
  const { rows } = await pool.query<Project>(q, values);
  return rows[0] || null;
}
