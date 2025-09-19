-- Extend project_languages with LOC and file count; update API and RPC; add total_loc to projects view

ALTER TABLE public.project_languages
  ADD COLUMN IF NOT EXISTS loc integer NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS files integer NOT NULL DEFAULT 0;

-- Refresh API view to expose new columns (drop first to allow column changes)
DO $$ BEGIN
  IF EXISTS (
    SELECT 1 FROM pg_proc p JOIN pg_namespace n ON p.pronamespace=n.oid
     WHERE n.nspname='api' AND p.proname='upsert_project_languages'
  ) THEN
    DROP FUNCTION IF EXISTS api.upsert_project_languages(bigint, jsonb);
  END IF;
END $$;
DROP VIEW IF EXISTS api.project_languages;
CREATE VIEW api.project_languages AS
  SELECT api_id AS id, id AS uuid, project_id, language, bytes, loc, files, is_primary, created_at
  FROM public.project_languages;

GRANT SELECT ON api.project_languages TO postgrest_anon;

-- Replace RPC to accept loc/files. Keep idempotent behavior.
CREATE OR REPLACE FUNCTION api.upsert_project_languages(
  p_project_id bigint,
  p_payload jsonb
)
RETURNS TABLE (
  id bigint,
  uuid uuid,
  project_id uuid,
  language text,
  bytes bigint,
  loc integer,
  files integer,
  is_primary boolean,
  created_at timestamptz
)
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

  -- Upsert rows. Coalesce to keep existing values when omitted by payload.
  INSERT INTO public.project_languages (project_id, language, bytes, loc, files)
  SELECT v_proj,
         (x->>'language')::text,
         COALESCE((x->>'bytes')::bigint, 0),
         COALESCE((x->>'loc')::int, 0),
         COALESCE((x->>'files')::int, 0)
  FROM jsonb_array_elements(p_payload) AS x
  ON CONFLICT (project_id, language)
  DO UPDATE SET bytes = COALESCE(NULLIF(EXCLUDED.bytes, 0), public.project_languages.bytes),
                loc   = COALESCE(NULLIF(EXCLUDED.loc, 0), public.project_languages.loc),
                files = COALESCE(NULLIF(EXCLUDED.files, 0), public.project_languages.files),
                updated_at = now()
  WHERE public.project_languages.bytes IS DISTINCT FROM COALESCE(NULLIF(EXCLUDED.bytes, 0), public.project_languages.bytes)
     OR public.project_languages.loc   IS DISTINCT FROM COALESCE(NULLIF(EXCLUDED.loc, 0),   public.project_languages.loc)
     OR public.project_languages.files IS DISTINCT FROM COALESCE(NULLIF(EXCLUDED.files, 0), public.project_languages.files);

  -- Recompute primary language = max(bytes), tie-breaker by language asc
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
  SELECT api_id AS id, id AS uuid, project_id, language, bytes, loc, files, is_primary, created_at
    FROM public.project_languages
   WHERE project_id = v_proj;
END;
$$;

GRANT EXECUTE ON FUNCTION api.upsert_project_languages(bigint, jsonb) TO postgrest_anon;

-- Recreate projects view to include primary_language and total_loc (sum of loc)
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
         (SELECT COALESCE(SUM(pl.loc), 0) FROM public.project_languages pl WHERE pl.project_id = p.id) AS total_loc,
         p.created_at,
         p.updated_at
  FROM public.projects p;

GRANT SELECT ON api.projects TO postgrest_anon;
