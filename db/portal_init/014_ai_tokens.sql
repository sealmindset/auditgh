-- 014_ai_tokens.sql
-- AI token detection and validation persistence (PLAINTEXT tokens per user request)

BEGIN;

-- Base table
CREATE TABLE IF NOT EXISTS public.ai_tokens (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  api_id bigserial UNIQUE,
  project_id uuid NOT NULL REFERENCES public.projects(id) ON DELETE CASCADE,
  repo_short text,
  provider text NOT NULL CHECK (provider IN (
    'openai','anthropic','gemini','cohere','mistral','stability','replicate','xai','ollama',
    'langchain','perplexity','wandb','cerebras','friendli','fireworks','nvidia_nim','together','zhipu','other'
  )),
  token text NOT NULL,
  file_path text,
  line_start int,
  line_end int,
  confidence text NOT NULL DEFAULT 'medium' CHECK (confidence IN ('low','medium','high')),
  validation_status text NOT NULL DEFAULT 'unknown' CHECK (validation_status IN ('unknown','valid','invalid','error')),
  validation_error text,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (project_id, provider, token)
);

CREATE INDEX IF NOT EXISTS ai_tokens_project_idx ON public.ai_tokens(project_id);
CREATE INDEX IF NOT EXISTS ai_tokens_provider_idx ON public.ai_tokens(provider);
CREATE INDEX IF NOT EXISTS ai_tokens_validation_idx ON public.ai_tokens(validation_status);

-- Optional validation audit trail
CREATE TABLE IF NOT EXISTS public.ai_tokens_validations (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  ai_token_id uuid NOT NULL REFERENCES public.ai_tokens(id) ON DELETE CASCADE,
  provider text NOT NULL,
  status text NOT NULL CHECK (status IN ('valid','invalid','error')),
  http_status int,
  error_message text,
  checked_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ai_tokens_validations_token_idx ON public.ai_tokens_validations(ai_token_id);

-- Row Level Security
ALTER TABLE public.ai_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.ai_tokens_validations ENABLE ROW LEVEL SECURITY;

-- Policies
-- Service role can do everything (assumes role exists and is used by server back-end)
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_roles WHERE rolname = 'postgrest_service'
  ) THEN RAISE NOTICE 'Role postgrest_service not found; create it before applying policies'; END IF;
END$$;

CREATE POLICY ai_tokens_service_all ON public.ai_tokens
  FOR ALL TO postgrest_service USING (true) WITH CHECK (true);
CREATE POLICY ai_tokens_validations_service_all ON public.ai_tokens_validations
  FOR ALL TO postgrest_service USING (true) WITH CHECK (true);

-- Deny anon by default; expose via API views only
REVOKE ALL ON public.ai_tokens FROM PUBLIC;
REVOKE ALL ON public.ai_tokens_validations FROM PUBLIC;

-- API schema views
CREATE SCHEMA IF NOT EXISTS api;

-- Non-admin view (no token column)
CREATE OR REPLACE VIEW api.ai_tokens AS
SELECT
  t.api_id AS id,
  p.name AS project_name,
  p.uuid AS project_uuid,
  t.repo_short,
  t.provider,
  t.confidence,
  t.validation_status,
  t.file_path,
  t.line_start,
  t.line_end,
  t.token,
  t.created_at,
  t.updated_at,
  t.metadata
FROM public.ai_tokens t
JOIN public.projects p ON p.id = t.project_id;

-- Admin view (includes token) — restrict to postgrest_admin
CREATE OR REPLACE VIEW api.ai_tokens_admin AS
SELECT
  t.api_id AS id,
  p.name AS project_name,
  p.uuid AS project_uuid,
  t.repo_short,
  t.provider,
  t.confidence,
  t.validation_status,
  t.file_path,
  t.line_start,
  t.line_end,
  t.token,
  t.created_at,
  t.updated_at,
  t.metadata
FROM public.ai_tokens t
JOIN public.projects p ON p.id = t.project_id;

-- Grant select on views
GRANT SELECT ON api.ai_tokens TO PUBLIC; -- readable by default (safe fields only)
GRANT SELECT ON api.ai_tokens_admin TO postgrest_admin; -- admin-only

-- RPCs
-- Upsert array payload under a project api_id
CREATE OR REPLACE FUNCTION api.upsert_ai_tokens(p_project_id int, p_payload jsonb)
RETURNS int
LANGUAGE plpgsql
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
    INSERT INTO public.ai_tokens (project_id, repo_short, provider, token, file_path, line_start, line_end, confidence, metadata)
    VALUES (
      v_proj_uuid,
      COALESCE(v_item->>'repo_short', NULL),
      v_item->>'provider',
      v_item->>'token',
      COALESCE(v_item->>'file_path', NULL),
      NULLIF((v_item->>'line_start')::int, NULL),
      NULLIF((v_item->>'line_end')::int, NULL),
      COALESCE(v_item->>'confidence','medium'),
      COALESCE(v_item->'metadata','{}'::jsonb)
    )
    ON CONFLICT (project_id, provider, token) DO UPDATE SET
      file_path = EXCLUDED.file_path,
      line_start = EXCLUDED.line_start,
      line_end = EXCLUDED.line_end,
      confidence = EXCLUDED.confidence,
      metadata = EXCLUDED.metadata,
      updated_at = now();
    v_count := v_count + 1;
  END LOOP;
  RETURN v_count;
END;
$$;

-- Record a validation result and update the token row
CREATE OR REPLACE FUNCTION api.record_ai_token_validation(p_ai_token_id int, p_status text, p_http_status int, p_error text)
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
  v_uuid uuid;
  v_status text;
BEGIN
  SELECT id INTO v_uuid FROM public.ai_tokens WHERE api_id = p_ai_token_id;
  IF v_uuid IS NULL THEN
    RAISE EXCEPTION 'ai_token with api_id % not found', p_ai_token_id;
  END IF;
  v_status := lower(p_status);
  IF v_status NOT IN ('valid','invalid','error') THEN
    v_status := 'error';
  END IF;

  INSERT INTO public.ai_tokens_validations (ai_token_id, provider, status, http_status, error_message)
  SELECT id, provider, v_status, p_http_status, p_error FROM public.ai_tokens WHERE id = v_uuid;

  UPDATE public.ai_tokens SET validation_status = CASE v_status
      WHEN 'valid' THEN 'valid'
      WHEN 'invalid' THEN 'invalid'
      ELSE 'error' END,
      validation_error = p_error,
      updated_at = now()
  WHERE id = v_uuid;
END;
$$;

COMMIT;
