-- Project languages persistence and projects view enhancement

-- Table to store per-project language composition
CREATE TABLE IF NOT EXISTS public.project_languages (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  api_id bigserial UNIQUE NOT NULL,
  project_id uuid NOT NULL REFERENCES public.projects(id) ON DELETE CASCADE,
  language text NOT NULL,
  bytes bigint NOT NULL DEFAULT 0,
  is_primary boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE(project_id, language)
);

CREATE INDEX IF NOT EXISTS idx_project_languages_project ON public.project_languages(project_id);
CREATE INDEX IF NOT EXISTS idx_project_languages_primary ON public.project_languages(project_id) WHERE is_primary;

-- updated_at trigger
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'project_languages_set_updated_at') THEN
    CREATE TRIGGER project_languages_set_updated_at BEFORE UPDATE ON public.project_languages FOR EACH ROW EXECUTE PROCEDURE set_updated_at();
  END IF;
END $$;

-- RLS
ALTER TABLE public.project_languages ENABLE ROW LEVEL SECURITY;

DO $$ BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_policies WHERE schemaname='public' AND tablename='project_languages' AND policyname='sel_project_languages_anon'
  ) THEN
    CREATE POLICY sel_project_languages_anon ON public.project_languages FOR SELECT TO postgrest_anon USING (true);
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_policies WHERE schemaname='public' AND tablename='project_languages' AND policyname='all_project_languages_app'
  ) THEN
    CREATE POLICY all_project_languages_app ON public.project_languages FOR ALL TO app USING (true) WITH CHECK (true);
  END IF;
END $$;

-- API view
CREATE OR REPLACE VIEW api.project_languages AS
  SELECT api_id AS id, id AS uuid, project_id, language, bytes, is_primary, created_at
  FROM public.project_languages;

GRANT SELECT ON api.project_languages TO postgrest_anon;

-- RPC: bulk upsert languages and recompute primary by max(bytes)
CREATE OR REPLACE FUNCTION api.upsert_project_languages(
  p_project_id bigint,
  p_payload jsonb
)
RETURNS SETOF api.project_languages
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  v_proj uuid;
BEGIN
  SELECT id INTO v_proj FROM public.projects WHERE api_id = p_project_id;
  IF v_proj IS NULL THEN
    RAISE EXCEPTION 'Project api_id % not found', p_project_id USING ERRCODE = 'foreign_key_violation';
  END IF;

  -- Upsert rows
  INSERT INTO public.project_languages (project_id, language, bytes)
  SELECT v_proj,
         (x->>'language')::text,
         COALESCE((x->>'bytes')::bigint, 0)
  FROM jsonb_array_elements(p_payload) AS x
  ON CONFLICT (project_id, language)
  DO UPDATE SET bytes = EXCLUDED.bytes,
                updated_at = now()
  WHERE public.project_languages.bytes IS DISTINCT FROM EXCLUDED.bytes;

  -- Recompute primary language by max(bytes) (tie-breaker: lowest language name)
  WITH ranked AS (
    SELECT pl.project_id, pl.language,
           ROW_NUMBER() OVER (
             PARTITION BY pl.project_id
             ORDER BY pl.bytes DESC, pl.language ASC
           ) AS rn
    FROM public.project_languages pl
    WHERE pl.project_id = v_proj
  )
  UPDATE public.project_languages t
     SET is_primary = (r.rn = 1),
         updated_at = now()
    FROM ranked r
   WHERE t.project_id = r.project_id AND t.language = r.language;

  RETURN QUERY
  SELECT api_id AS id, id AS uuid, project_id, language, bytes, is_primary, created_at
    FROM public.project_languages
   WHERE project_id = v_proj;
END;
$$;

GRANT EXECUTE ON FUNCTION api.upsert_project_languages(bigint, jsonb) TO postgrest_anon;

-- Enhance api.projects to expose primary_language (recreate view here to ensure dependency order)
DROP VIEW IF EXISTS api.projects;
CREATE VIEW api.projects AS
  SELECT p.api_id AS id,
         p.id AS uuid,
         p.name,
         p.repo_url,
         p.description,
         p.is_active,
         p.contributors_count,
         p.last_commit_at,
         (SELECT pl.language FROM public.project_languages pl WHERE pl.project_id = p.id AND pl.is_primary LIMIT 1) AS primary_language,
         p.created_at,
         p.updated_at
  FROM public.projects p;

GRANT SELECT ON api.projects TO postgrest_anon;
