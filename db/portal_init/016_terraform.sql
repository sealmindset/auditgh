-- Terraform findings persistence (tables, RLS, API view)
-- Follows ID conventions: UUID id (internal), api_id bigserial (external via PostgREST)

-- Table
CREATE TABLE IF NOT EXISTS public.terraform_findings (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  api_id bigserial UNIQUE NOT NULL,
  project_id uuid NOT NULL REFERENCES public.projects(id) ON DELETE CASCADE,
  repo_short text NOT NULL,
  scanner text NOT NULL CHECK (scanner IN ('checkov','trivy')),
  rule_id text NOT NULL,
  rule_name text,
  severity text NOT NULL CHECK (lower(severity) IN ('critical','high','medium','low','unknown')),
  resource text,
  file_path text NOT NULL,
  line_start integer NOT NULL DEFAULT 0,
  guideline_url text,
  created_at timestamptz NOT NULL DEFAULT now()
);

-- Uniqueness to prevent duplicates from repeated ingests
DO $$ BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'terraform_findings_uniq'
  ) THEN
    ALTER TABLE public.terraform_findings
      ADD CONSTRAINT terraform_findings_uniq UNIQUE (project_id, repo_short, scanner, rule_id, file_path, line_start);
  END IF;
END $$;

-- Indexes
CREATE INDEX IF NOT EXISTS terraform_findings_project_id_idx ON public.terraform_findings(project_id);
CREATE INDEX IF NOT EXISTS terraform_findings_repo_short_idx ON public.terraform_findings(repo_short);
CREATE INDEX IF NOT EXISTS terraform_findings_scanner_idx ON public.terraform_findings(scanner);
CREATE INDEX IF NOT EXISTS terraform_findings_severity_idx ON public.terraform_findings((lower(severity)));

-- RLS
ALTER TABLE public.terraform_findings ENABLE ROW LEVEL SECURITY;
DO $$ BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'terraform_findings' AND policyname = 'sel_terraform_findings_anon'
  ) THEN
    CREATE POLICY sel_terraform_findings_anon ON public.terraform_findings FOR SELECT TO postgrest_anon USING (true);
  END IF;
END $$;
DO $$ BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'terraform_findings' AND policyname = 'all_terraform_findings_app'
  ) THEN
    CREATE POLICY all_terraform_findings_app ON public.terraform_findings FOR ALL TO app USING (true) WITH CHECK (true);
  END IF;
END $$;

-- API view
CREATE SCHEMA IF NOT EXISTS api;
GRANT USAGE ON SCHEMA api TO postgrest_anon;

CREATE OR REPLACE VIEW api.terraform_findings AS
  SELECT api_id AS id,
         project_id,
         repo_short,
         scanner,
         rule_id,
         rule_name,
         lower(severity) AS severity,
         resource,
         file_path,
         line_start,
         guideline_url,
         created_at
  FROM public.terraform_findings;

GRANT SELECT ON ALL TABLES IN SCHEMA api TO postgrest_anon;
