-- Binaries findings persistence (tables, RLS, API view)
-- Follows ID conventions: UUID id (internal), api_id bigserial (external via PostgREST)

-- Table
CREATE TABLE IF NOT EXISTS public.binaries_findings (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  api_id bigserial UNIQUE NOT NULL,
  project_id uuid NOT NULL REFERENCES public.projects(id) ON DELETE CASCADE,
  repo_short text NOT NULL,
  path text NOT NULL,
  filename text NOT NULL,
  extension text NOT NULL DEFAULT '',
  size_bytes bigint NOT NULL,
  is_executable boolean NOT NULL DEFAULT false,
  type text NOT NULL,
  sha256 text NOT NULL DEFAULT '',
  mode text NOT NULL DEFAULT '',
  created_at timestamptz NOT NULL DEFAULT now()
);

-- Uniqueness to prevent duplicates from repeated ingests
DO $$ BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'binaries_findings_uniq'
  ) THEN
    ALTER TABLE public.binaries_findings
      ADD CONSTRAINT binaries_findings_uniq UNIQUE (project_id, repo_short, path, sha256);
  END IF;
END $$;

-- Indexes
CREATE INDEX IF NOT EXISTS binaries_findings_project_id_idx ON public.binaries_findings(project_id);
CREATE INDEX IF NOT EXISTS binaries_findings_repo_short_idx ON public.binaries_findings(repo_short);
CREATE INDEX IF NOT EXISTS binaries_findings_exec_idx ON public.binaries_findings(is_executable);
CREATE INDEX IF NOT EXISTS binaries_findings_ext_idx ON public.binaries_findings(extension);

-- RLS
ALTER TABLE public.binaries_findings ENABLE ROW LEVEL SECURITY;
DO $$ BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'binaries_findings' AND policyname = 'sel_binaries_findings_anon'
  ) THEN
    CREATE POLICY sel_binaries_findings_anon ON public.binaries_findings FOR SELECT TO postgrest_anon USING (true);
  END IF;
END $$;
DO $$ BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'binaries_findings' AND policyname = 'all_binaries_findings_app'
  ) THEN
    CREATE POLICY all_binaries_findings_app ON public.binaries_findings FOR ALL TO app USING (true) WITH CHECK (true);
  END IF;
END $$;

-- API view
CREATE SCHEMA IF NOT EXISTS api;
GRANT USAGE ON SCHEMA api TO postgrest_anon;

CREATE OR REPLACE VIEW api.binaries_findings AS
  SELECT api_id AS id,
         project_id,
         repo_short,
         path,
         filename,
         extension,
         size_bytes,
         is_executable,
         type,
         sha256,
         mode,
         created_at
  FROM public.binaries_findings;

GRANT SELECT ON ALL TABLES IN SCHEMA api TO postgrest_anon;
