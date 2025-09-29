-- AI Assist analyses persistence (tables, RLS, API view)
-- Follows ID conventions: UUID id (internal), api_id bigserial (external via PostgREST)

-- Table
CREATE TABLE IF NOT EXISTS public.ai_assist_analyses (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  api_id bigserial UNIQUE NOT NULL,
  project_id uuid NULL REFERENCES public.projects(id) ON DELETE SET NULL,
  repo_short text NULL,
  target text NOT NULL CHECK (target IN ('terraform','oss','codeql','secret','cicd')),
  provider text NOT NULL CHECK (provider IN ('ollama','openai')),
  model text NOT NULL,
  prompt_text text NOT NULL,
  request_context jsonb NOT NULL DEFAULT '{}'::jsonb,
  reference_urls jsonb NOT NULL DEFAULT '[]'::jsonb,
  reference_extracts jsonb NOT NULL DEFAULT '[]'::jsonb,
  response_text text,
  status text NOT NULL DEFAULT 'completed',
  duration_ms integer NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  created_by text NULL
);

-- Indexes
CREATE INDEX IF NOT EXISTS ai_assist_analyses_project_id_idx ON public.ai_assist_analyses(project_id);
CREATE INDEX IF NOT EXISTS ai_assist_analyses_repo_short_idx ON public.ai_assist_analyses(repo_short);
CREATE INDEX IF NOT EXISTS ai_assist_analyses_created_at_idx ON public.ai_assist_analyses(created_at DESC);

-- RLS
ALTER TABLE public.ai_assist_analyses ENABLE ROW LEVEL SECURITY;
DO $$ BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'ai_assist_analyses' AND policyname = 'sel_ai_assist_analyses_anon'
  ) THEN
    CREATE POLICY sel_ai_assist_analyses_anon ON public.ai_assist_analyses FOR SELECT TO postgrest_anon USING (true);
  END IF;
END $$;
DO $$ BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'ai_assist_analyses' AND policyname = 'all_ai_assist_analyses_app'
  ) THEN
    CREATE POLICY all_ai_assist_analyses_app ON public.ai_assist_analyses FOR ALL TO app USING (true) WITH CHECK (true);
  END IF;
END $$;

-- API view
CREATE SCHEMA IF NOT EXISTS api;
GRANT USAGE ON SCHEMA api TO postgrest_anon;

CREATE OR REPLACE VIEW api.ai_assist_analyses AS
  SELECT api_id AS id,
         id AS uuid,
         project_id,
         repo_short,
         target,
         provider,
         model,
         prompt_text,
         request_context,
         reference_urls,
         reference_extracts,
         response_text,
         status,
         duration_ms,
         created_at,
         created_by
  FROM public.ai_assist_analyses;

GRANT SELECT ON ALL TABLES IN SCHEMA api TO postgrest_anon;
