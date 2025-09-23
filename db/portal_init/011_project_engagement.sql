-- Project engagement snapshots: stars, forks, watchers, open_issues, commits, collaborators

-- Table
CREATE TABLE IF NOT EXISTS public.project_engagement_snapshots (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  api_id bigserial UNIQUE NOT NULL,
  project_id uuid NOT NULL REFERENCES public.projects(id) ON DELETE CASCADE,
  observed_at timestamptz NOT NULL DEFAULT now(),
  stars integer NOT NULL DEFAULT 0,
  forks integer NOT NULL DEFAULT 0,
  watchers integer NOT NULL DEFAULT 0,
  open_issues integer NOT NULL DEFAULT 0,
  commits integer DEFAULT 0,
  collaborators integer DEFAULT 0,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE(project_id, observed_at)
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_project_engagement_project_time ON public.project_engagement_snapshots(project_id, observed_at DESC);

-- updated_at trigger
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'project_engagement_snapshots_set_updated_at') THEN
    CREATE TRIGGER project_engagement_snapshots_set_updated_at
    BEFORE UPDATE ON public.project_engagement_snapshots
    FOR EACH ROW EXECUTE PROCEDURE set_updated_at();
  END IF;
END $$;

-- RLS
ALTER TABLE public.project_engagement_snapshots ENABLE ROW LEVEL SECURITY;

DO $$ BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_policies WHERE schemaname='public' AND tablename='project_engagement_snapshots' AND policyname='sel_project_engagement_anon'
  ) THEN
    CREATE POLICY sel_project_engagement_anon ON public.project_engagement_snapshots FOR SELECT TO postgrest_anon USING (true);
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_policies WHERE schemaname='public' AND tablename='project_engagement_snapshots' AND policyname='all_project_engagement_app'
  ) THEN
    CREATE POLICY all_project_engagement_app ON public.project_engagement_snapshots FOR ALL TO app USING (true) WITH CHECK (true);
  END IF;
END $$;

-- API view
CREATE OR REPLACE VIEW api.project_engagement_snapshots AS
  SELECT api_id AS id, id AS uuid, project_id, observed_at, stars, forks, watchers, open_issues, commits, collaborators, created_at
  FROM public.project_engagement_snapshots;

GRANT SELECT ON api.project_engagement_snapshots TO postgrest_anon;

-- RPC: upsert/bulk-insert engagement snapshots (idempotent by project_id+observed_at)
CREATE OR REPLACE FUNCTION api.upsert_project_engagement(
  p_project_id bigint,
  p_payload jsonb
)
RETURNS SETOF api.project_engagement_snapshots
LANGUAGE sql
SECURITY DEFINER
SET search_path = public
AS $$
  WITH proj AS (
    SELECT id FROM public.projects WHERE api_id = p_project_id
  ), ins AS (
    INSERT INTO public.project_engagement_snapshots (project_id, observed_at, stars, forks, watchers, open_issues, commits, collaborators)
    SELECT (SELECT id FROM proj),
           COALESCE((x->>'observed_at')::timestamptz, now()),
           COALESCE((x->>'stars')::int, 0),
           COALESCE((x->>'forks')::int, 0),
           COALESCE((x->>'watchers')::int, 0),
           COALESCE((x->>'open_issues')::int, 0),
           COALESCE((x->>'commits')::int, 0),
           COALESCE((x->>'collaborators')::int, 0)
    FROM jsonb_array_elements(p_payload) AS x
    ON CONFLICT (project_id, observed_at)
    DO UPDATE SET stars = EXCLUDED.stars,
                  forks = EXCLUDED.forks,
                  watchers = EXCLUDED.watchers,
                  open_issues = EXCLUDED.open_issues,
                  commits = EXCLUDED.commits,
                  collaborators = EXCLUDED.collaborators,
                  updated_at = now()
    RETURNING *
  )
  SELECT api_id AS id, id AS uuid, project_id, observed_at, stars, forks, watchers, open_issues, commits, collaborators, created_at
    FROM ins;
$$;

GRANT EXECUTE ON FUNCTION api.upsert_project_engagement(bigint, jsonb) TO postgrest_anon;

-- Recreate api.projects to include stars and forks from latest snapshot (if available)
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
         es.stars,
         es.forks,
         p.created_at,
         p.updated_at
  FROM public.projects p
  LEFT JOIN LATERAL (
    SELECT s.stars, s.forks
      FROM public.project_engagement_snapshots s
     WHERE s.project_id = p.id
     ORDER BY s.observed_at DESC
     LIMIT 1
  ) es ON true;

GRANT SELECT ON api.projects TO postgrest_anon;
