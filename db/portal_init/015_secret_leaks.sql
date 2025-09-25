-- 015_secret_leaks.sql
-- Generic secret leak persistence (Gitleaks, TruffleHog, etc.)

BEGIN;

CREATE TABLE IF NOT EXISTS public.secret_leaks (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  api_id bigserial UNIQUE,
  project_id uuid NOT NULL REFERENCES public.projects(id) ON DELETE CASCADE,
  repo_short text,
  detector text NOT NULL CHECK (detector IN ('gitleaks','trufflehog','genai','other')),
  rule_id text,
  description text,
  secret text NOT NULL,
  file_path text,
  line_start int,
  line_end int,
  confidence text NOT NULL DEFAULT 'medium' CHECK (confidence IN ('low','medium','high')),
  validation_status text NOT NULL DEFAULT 'unknown' CHECK (validation_status IN ('unknown','valid','invalid','error')),
  validation_error text,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT secret_leaks_project_detector_rule_file_line_unique
    UNIQUE (project_id, detector, rule_id, secret, file_path, line_start)
);

CREATE INDEX IF NOT EXISTS secret_leaks_project_idx ON public.secret_leaks(project_id);
CREATE INDEX IF NOT EXISTS secret_leaks_detector_idx ON public.secret_leaks(detector);
CREATE INDEX IF NOT EXISTS secret_leaks_validation_idx ON public.secret_leaks(validation_status);

CREATE TABLE IF NOT EXISTS public.secret_leak_validations (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  secret_leak_id uuid NOT NULL REFERENCES public.secret_leaks(id) ON DELETE CASCADE,
  detector text NOT NULL,
  status text NOT NULL CHECK (status IN ('valid','invalid','error')),
  http_status int,
  error_message text,
  checked_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS secret_leak_validations_idx ON public.secret_leak_validations(secret_leak_id);

ALTER TABLE public.secret_leaks ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.secret_leak_validations ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'postgrest_service') THEN
    RAISE NOTICE 'Role postgrest_service not found; create it before applying policies';
  END IF;
END$$;

CREATE POLICY secret_leaks_service_all ON public.secret_leaks
  FOR ALL TO postgrest_service USING (true) WITH CHECK (true);
CREATE POLICY secret_leak_validations_service_all ON public.secret_leak_validations
  FOR ALL TO postgrest_service USING (true) WITH CHECK (true);

REVOKE ALL ON public.secret_leaks FROM PUBLIC;
REVOKE ALL ON public.secret_leak_validations FROM PUBLIC;

CREATE SCHEMA IF NOT EXISTS api;

CREATE OR REPLACE VIEW api.secret_leaks AS
SELECT
  l.api_id AS id,
  p.name AS project_name,
  p.id AS project_uuid,
  l.repo_short,
  l.detector,
  l.rule_id,
  l.description,
  l.file_path,
  l.line_start,
  l.line_end,
  l.confidence,
  l.validation_status,
  l.validation_error,
  l.created_at,
  l.updated_at,
  l.metadata
FROM public.secret_leaks l
JOIN public.projects p ON p.id = l.project_id;

CREATE OR REPLACE VIEW api.secret_leaks_admin AS
SELECT
  l.api_id AS id,
  p.name AS project_name,
  p.id AS project_uuid,
  l.repo_short,
  l.detector,
  l.rule_id,
  l.description,
  l.secret,
  l.file_path,
  l.line_start,
  l.line_end,
  l.confidence,
  l.validation_status,
  l.validation_error,
  l.created_at,
  l.updated_at,
  l.metadata
FROM public.secret_leaks l
JOIN public.projects p ON p.id = l.project_id;

GRANT SELECT ON api.secret_leaks TO PUBLIC;
GRANT SELECT ON api.secret_leaks_admin TO postgrest_admin;

CREATE OR REPLACE FUNCTION api.upsert_secret_leaks(p_project_id int, p_payload jsonb)
RETURNS int
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  v_count int := 0;
  v_proj_uuid uuid;
  v_item jsonb;
BEGIN
  SELECT id INTO v_proj_uuid FROM public.projects WHERE api_id = p_project_id;
  IF v_proj_uuid IS NULL THEN
    RAISE EXCEPTION 'Project with api_id % not found', p_project_id;
  END IF;

  FOR v_item IN SELECT * FROM jsonb_array_elements(COALESCE(p_payload, '[]'::jsonb)) LOOP
    INSERT INTO public.secret_leaks (
      project_id,
      repo_short,
      detector,
      rule_id,
      description,
      secret,
      file_path,
      line_start,
      line_end,
      confidence,
      validation_status,
      metadata
    ) VALUES (
      v_proj_uuid,
      NULLIF(v_item->>'repo_short',''),
      COALESCE(v_item->>'detector','other'),
      NULLIF(v_item->>'rule_id',''),
      NULLIF(v_item->>'description',''),
      v_item->>'secret',
      NULLIF(v_item->>'file_path',''),
      NULLIF(v_item->>'line_start','')::int,
      NULLIF(v_item->>'line_end','')::int,
      COALESCE(v_item->>'confidence','medium'),
      COALESCE(v_item->>'validation_status','unknown'),
      COALESCE(v_item->'metadata', '{}'::jsonb)
    )
    ON CONFLICT ON CONSTRAINT secret_leaks_project_detector_rule_file_line_unique DO UPDATE
      SET
        description = EXCLUDED.description,
        file_path = EXCLUDED.file_path,
        line_start = EXCLUDED.line_start,
        line_end = EXCLUDED.line_end,
        confidence = EXCLUDED.confidence,
        validation_status = EXCLUDED.validation_status,
        metadata = EXCLUDED.metadata,
        updated_at = now();
    v_count := v_count + 1;
  END LOOP;

  RETURN v_count;
END;
$$;

CREATE OR REPLACE FUNCTION api.record_secret_leak_validation(
  p_secret_leak_id int,
  p_status text,
  p_http_status int,
  p_error text
) RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  v_uuid uuid;
  v_status text;
BEGIN
  SELECT id INTO v_uuid FROM public.secret_leaks WHERE api_id = p_secret_leak_id;
  IF v_uuid IS NULL THEN
    RAISE EXCEPTION 'secret_leak with api_id % not found', p_secret_leak_id;
  END IF;

  IF p_status IS NULL OR p_status NOT IN ('valid','invalid','error') THEN
    v_status := 'error';
  ELSE
    v_status := p_status;
  END IF;

  INSERT INTO public.secret_leak_validations (secret_leak_id, detector, status, http_status, error_message)
  SELECT id, detector, v_status, p_http_status, p_error FROM public.secret_leaks WHERE id = v_uuid;

  UPDATE public.secret_leaks
  SET validation_status = CASE v_status
      WHEN 'valid' THEN 'valid'
      WHEN 'invalid' THEN 'invalid'
      ELSE 'error' END,
      validation_error = p_error,
      updated_at = now()
  WHERE id = v_uuid;
END;
$$;

GRANT EXECUTE ON FUNCTION api.upsert_secret_leaks(int, jsonb) TO postgrest_service, postgrest_anon, postgrest_admin;
GRANT EXECUTE ON FUNCTION api.record_secret_leak_validation(int, text, int, text) TO postgrest_service, postgrest_anon, postgrest_admin;

COMMIT;
