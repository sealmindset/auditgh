-- CodeQL persistence tables, RLS, and API views for dashboard and findings
-- Applies after base schema and api schema creation

-- Tables
CREATE TABLE IF NOT EXISTS public.codeql_findings (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  api_id bigserial UNIQUE NOT NULL,
  project_id uuid NOT NULL REFERENCES public.projects(id) ON DELETE CASCADE,
  scan_id uuid NOT NULL REFERENCES public.scans(id) ON DELETE CASCADE,
  repo_short text NOT NULL,
  language text,
  rule_id text NOT NULL,
  rule_name text,
  severity text NOT NULL CHECK (severity IN ('critical','high','medium','low','info','unknown')),
  file text NOT NULL,
  line integer NOT NULL DEFAULT 0,
  message text NOT NULL,
  help_uri text,
  unique_key text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

DO $$ BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'codeql_findings_unique_key_uniq'
  ) THEN
    ALTER TABLE public.codeql_findings ADD CONSTRAINT codeql_findings_unique_key_uniq UNIQUE (unique_key);
  END IF;
END $$;

CREATE INDEX IF NOT EXISTS codeql_findings_project_id_idx ON public.codeql_findings(project_id);
CREATE INDEX IF NOT EXISTS codeql_findings_scan_id_idx ON public.codeql_findings(scan_id);
CREATE INDEX IF NOT EXISTS codeql_findings_repo_short_idx ON public.codeql_findings(repo_short);
CREATE INDEX IF NOT EXISTS codeql_findings_severity_idx ON public.codeql_findings(severity);
CREATE INDEX IF NOT EXISTS codeql_findings_rule_id_idx ON public.codeql_findings(rule_id);
CREATE INDEX IF NOT EXISTS codeql_findings_language_idx ON public.codeql_findings(language);

CREATE TABLE IF NOT EXISTS public.codeql_scan_repos (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  api_id bigserial UNIQUE NOT NULL,
  project_id uuid NOT NULL REFERENCES public.projects(id) ON DELETE CASCADE,
  scan_id uuid NOT NULL REFERENCES public.scans(id) ON DELETE CASCADE,
  repo_short text NOT NULL,
  language text,
  has_sarif boolean NOT NULL DEFAULT true,
  findings_count integer NOT NULL DEFAULT 0,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (scan_id, repo_short, language)
);

CREATE INDEX IF NOT EXISTS codeql_scan_repos_project_id_idx ON public.codeql_scan_repos(project_id);
CREATE INDEX IF NOT EXISTS codeql_scan_repos_scan_id_idx ON public.codeql_scan_repos(scan_id);
CREATE INDEX IF NOT EXISTS codeql_scan_repos_repo_short_idx ON public.codeql_scan_repos(repo_short);

-- RLS (Row Level Security)
ALTER TABLE public.codeql_findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.codeql_scan_repos ENABLE ROW LEVEL SECURITY;

DO $$ BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'codeql_findings' AND policyname = 'sel_codeql_findings_anon'
  ) THEN
    CREATE POLICY sel_codeql_findings_anon ON public.codeql_findings FOR SELECT TO postgrest_anon USING (true);
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'codeql_scan_repos' AND policyname = 'sel_codeql_scan_repos_anon'
  ) THEN
    CREATE POLICY sel_codeql_scan_repos_anon ON public.codeql_scan_repos FOR SELECT TO postgrest_anon USING (true);
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'codeql_findings' AND policyname = 'all_codeql_findings_app'
  ) THEN
    CREATE POLICY all_codeql_findings_app ON public.codeql_findings FOR ALL TO app USING (true) WITH CHECK (true);
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'codeql_scan_repos' AND policyname = 'all_codeql_scan_repos_app'
  ) THEN
    CREATE POLICY all_codeql_scan_repos_app ON public.codeql_scan_repos FOR ALL TO app USING (true) WITH CHECK (true);
  END IF;
END $$;

-- API schema and views
CREATE SCHEMA IF NOT EXISTS api;
GRANT USAGE ON SCHEMA api TO postgrest_anon;

CREATE OR REPLACE VIEW api.codeql_findings AS
  SELECT api_id AS id, project_id, scan_id, repo_short, language, rule_id, rule_name,
         severity, file, line, message, help_uri, created_at
  FROM public.codeql_findings;

CREATE OR REPLACE VIEW api.codeql_scan_repos AS
  SELECT api_id AS id, project_id, scan_id, repo_short, language, has_sarif, findings_count, created_at
  FROM public.codeql_scan_repos;

CREATE OR REPLACE VIEW api.codeql_org_severity_totals AS
  SELECT
    COUNT(*)::int AS total,
    COALESCE(SUM(CASE WHEN lower(severity) = 'critical' THEN 1 ELSE 0 END), 0)::int AS critical,
    COALESCE(SUM(CASE WHEN lower(severity) = 'high' THEN 1 ELSE 0 END), 0)::int AS high,
    COALESCE(SUM(CASE WHEN lower(severity) = 'medium' THEN 1 ELSE 0 END), 0)::int AS medium,
    COALESCE(SUM(CASE WHEN lower(severity) = 'low' THEN 1 ELSE 0 END), 0)::int AS low,
    COALESCE(SUM(CASE WHEN lower(severity) = 'info' THEN 1 ELSE 0 END), 0)::int AS info,
    COALESCE(SUM(CASE WHEN lower(severity) = 'unknown' THEN 1 ELSE 0 END), 0)::int AS unknown
  FROM public.codeql_findings;

CREATE OR REPLACE VIEW api.codeql_org_top_repos AS
  SELECT
    cf.project_id,
    p.name AS project_name,
    cf.repo_short AS repo,
    SUM(CASE WHEN lower(cf.severity) = 'critical' THEN 1 ELSE 0 END)::int AS critical,
    SUM(CASE WHEN lower(cf.severity) = 'high' THEN 1 ELSE 0 END)::int AS high,
    SUM(CASE WHEN lower(cf.severity) = 'medium' THEN 1 ELSE 0 END)::int AS medium,
    SUM(CASE WHEN lower(cf.severity) = 'low' THEN 1 ELSE 0 END)::int AS low,
    SUM(CASE WHEN lower(cf.severity) = 'info' THEN 1 ELSE 0 END)::int AS info,
    COUNT(*)::int AS total
  FROM public.codeql_findings cf
  JOIN public.projects p ON p.id = cf.project_id
  GROUP BY cf.project_id, p.name, cf.repo_short;

CREATE OR REPLACE VIEW api.codeql_recent_scans AS
  SELECT
    s.id AS scan_id,
    s.project_id,
    p.name AS project_name,
    s.profile,
    s.status,
    s.finished_at,
    COALESCE(f.cnt, 0)::int AS findings_count,
    COALESCE(r.repos, 0)::int AS repositories
  FROM public.scans s
  JOIN public.projects p ON p.id = s.project_id
  LEFT JOIN (
    SELECT scan_id, COUNT(*)::int AS cnt FROM public.codeql_findings GROUP BY scan_id
  ) f ON f.scan_id = s.id
  LEFT JOIN (
    SELECT scan_id, COUNT(DISTINCT repo_short)::int AS repos FROM public.codeql_scan_repos GROUP BY scan_id
  ) r ON r.scan_id = s.id
  ORDER BY s.finished_at DESC NULLS LAST;

GRANT SELECT ON ALL TABLES IN SCHEMA api TO postgrest_anon;
