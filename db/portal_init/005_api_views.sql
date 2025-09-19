CREATE SCHEMA IF NOT EXISTS api;
GRANT USAGE ON SCHEMA api TO postgrest_anon;

DROP VIEW IF EXISTS api.projects;
CREATE VIEW api.projects AS
  SELECT api_id AS id, id AS uuid, name, repo_url, description, is_active,
         contributors_count, last_commit_at, created_at, updated_at
  FROM public.projects;

CREATE OR REPLACE VIEW api.scans AS
  SELECT api_id AS id, id AS uuid, project_id, profile, status, started_at, finished_at, created_at
  FROM public.scans;

CREATE OR REPLACE VIEW api.findings AS
  SELECT api_id AS id, id AS uuid, project_id, scan_id, source, rule_id, title, severity, status, kev_id, epss_score, tags, created_at
  FROM public.findings;

GRANT SELECT ON ALL TABLES IN SCHEMA api TO postgrest_anon;

-- Upsert/update helper for projects via PostgREST RPC
-- Returns the api.projects row shape
CREATE OR REPLACE FUNCTION api.update_project(
  p_uuid uuid,
  p_name text DEFAULT NULL,
  p_repo_url text DEFAULT NULL,
  p_description text DEFAULT NULL,
  p_is_active boolean DEFAULT NULL
)
RETURNS TABLE (
  id bigint,
  uuid uuid,
  name text,
  repo_url text,
  description text,
  is_active boolean,
  created_at timestamptz
)
LANGUAGE sql
SECURITY DEFINER
SET search_path = public
AS $$
  UPDATE public.projects
     SET name = COALESCE(p_name, name),
         repo_url = COALESCE(p_repo_url, repo_url),
         description = COALESCE(p_description, description),
         is_active = COALESCE(p_is_active, is_active),
         updated_at = now()
   WHERE id = p_uuid
RETURNING api_id, id, name, repo_url, description, is_active, created_at;
$$;

GRANT EXECUTE ON FUNCTION api.update_project(uuid, text, text, text, boolean) TO postgrest_anon;

-- Ensure a project exists by name; update repo_url/description if provided
CREATE OR REPLACE FUNCTION api.ensure_project(
  p_name text,
  p_repo_url text DEFAULT NULL,
  p_description text DEFAULT NULL
)
RETURNS TABLE (
  id bigint,
  uuid uuid,
  name text,
  repo_url text,
  description text,
  is_active boolean,
  created_at timestamptz
)
LANGUAGE sql
SECURITY DEFINER
SET search_path = public
AS $$
  WITH upsert AS (
    INSERT INTO public.projects (name, repo_url, description)
         VALUES (p_name, p_repo_url, p_description)
    ON CONFLICT (name)
      DO UPDATE SET repo_url = COALESCE(EXCLUDED.repo_url, projects.repo_url),
                    description = COALESCE(EXCLUDED.description, projects.description),
                    updated_at = now()
      WHERE (projects.repo_url IS DISTINCT FROM EXCLUDED.repo_url)
         OR (projects.description IS DISTINCT FROM EXCLUDED.description)
    RETURNING api_id, id, name, repo_url, description, is_active, created_at
  )
  SELECT * FROM upsert
  UNION ALL
  SELECT api_id, id, name, repo_url, description, is_active, created_at
    FROM public.projects
   WHERE name = p_name
     AND NOT EXISTS (SELECT 1 FROM upsert);
$$;

GRANT EXECUTE ON FUNCTION api.ensure_project(text, text, text) TO postgrest_anon;
