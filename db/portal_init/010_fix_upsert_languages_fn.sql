-- Fix ambiguous column references in api.upsert_project_languages by qualifying table columns

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
  SELECT p.id INTO v_proj FROM public.projects p WHERE p.api_id = p_project_id;
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
  ON CONFLICT ON CONSTRAINT project_languages_project_id_language_key
  DO UPDATE SET bytes = COALESCE(NULLIF(EXCLUDED.bytes, 0), public.project_languages.bytes),
                loc   = COALESCE(NULLIF(EXCLUDED.loc, 0), public.project_languages.loc),
                files = COALESCE(NULLIF(EXCLUDED.files, 0), public.project_languages.files),
                updated_at = now()
  WHERE public.project_languages.bytes IS DISTINCT FROM COALESCE(NULLIF(EXCLUDED.bytes, 0), public.project_languages.bytes)
     OR public.project_languages.loc   IS DISTINCT FROM COALESCE(NULLIF(EXCLUDED.loc, 0),   public.project_languages.loc)
     OR public.project_languages.files IS DISTINCT FROM COALESCE(NULLIF(EXCLUDED.files, 0), public.project_languages.files);

  -- Recompute primary language by max(bytes)
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
  SELECT pl.api_id AS id,
         pl.id AS uuid,
         pl.project_id,
         pl.language,
         pl.bytes,
         pl.loc,
         pl.files,
         pl.is_primary,
         pl.created_at
    FROM public.project_languages pl
   WHERE pl.project_id = v_proj;
END;
$$;
