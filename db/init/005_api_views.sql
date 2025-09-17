-- Read-only API schema for PostgREST
CREATE SCHEMA IF NOT EXISTS api;
GRANT USAGE ON SCHEMA api TO postgrest_anon;

CREATE OR REPLACE VIEW api.projects AS
  SELECT api_id AS id, id AS uuid, name, repo_url, description, is_active, created_at
  FROM public.projects;

CREATE OR REPLACE VIEW api.scans AS
  SELECT api_id AS id, id AS uuid, project_id, profile, status, started_at, finished_at, created_at
  FROM public.scans;

CREATE OR REPLACE VIEW api.findings AS
  SELECT api_id AS id, id AS uuid, project_id, scan_id, source, rule_id, title, severity, status, kev_id, epss_score, tags, created_at
  FROM public.findings;

GRANT SELECT ON ALL TABLES IN SCHEMA api TO postgrest_anon;
