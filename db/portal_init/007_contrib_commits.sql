-- Project contributors and commits persistence

-- Project summary columns
ALTER TABLE public.projects
  ADD COLUMN IF NOT EXISTS contributors_count integer NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS last_commit_at timestamptz;

-- Tables
CREATE TABLE IF NOT EXISTS public.project_contributors (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  api_id bigserial UNIQUE NOT NULL,
  project_id uuid NOT NULL REFERENCES public.projects(id) ON DELETE CASCADE,
  gh_user_id bigint,
  login text NOT NULL,
  display_name text,
  email text,
  commits_count integer NOT NULL DEFAULT 0,
  first_commit_at timestamptz,
  last_commit_at timestamptz,
  lines_added integer DEFAULT 0,
  lines_deleted integer DEFAULT 0,
  is_bot boolean NOT NULL DEFAULT false,
  risk_score numeric,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE(project_id, login)
);

CREATE INDEX IF NOT EXISTS idx_project_contributors_project ON public.project_contributors(project_id);
CREATE INDEX IF NOT EXISTS idx_project_contributors_last_commit ON public.project_contributors(project_id, last_commit_at DESC);

CREATE TABLE IF NOT EXISTS public.project_commits (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  api_id bigserial UNIQUE NOT NULL,
  project_id uuid NOT NULL REFERENCES public.projects(id) ON DELETE CASCADE,
  sha text NOT NULL,
  author_login text,
  author_email text,
  committed_at timestamptz NOT NULL,
  additions integer,
  deletions integer,
  files_changed integer,
  message text,
  url text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE(project_id, sha)
);

CREATE INDEX IF NOT EXISTS idx_project_commits_project ON public.project_commits(project_id);
CREATE INDEX IF NOT EXISTS idx_project_commits_time ON public.project_commits(project_id, committed_at DESC);

-- Updated_at triggers
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'project_contributors_set_updated_at') THEN
    CREATE TRIGGER project_contributors_set_updated_at BEFORE UPDATE ON public.project_contributors FOR EACH ROW EXECUTE PROCEDURE set_updated_at();
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'project_commits_set_updated_at') THEN
    CREATE TRIGGER project_commits_set_updated_at BEFORE UPDATE ON public.project_commits FOR EACH ROW EXECUTE PROCEDURE set_updated_at();
  END IF;
END $$;

-- RLS
ALTER TABLE public.project_contributors ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.project_commits ENABLE ROW LEVEL SECURITY;

DO $$ BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_policies WHERE schemaname='public' AND tablename='project_contributors' AND policyname='sel_project_contributors_anon'
  ) THEN
    CREATE POLICY sel_project_contributors_anon ON public.project_contributors FOR SELECT TO postgrest_anon USING (true);
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_policies WHERE schemaname='public' AND tablename='project_commits' AND policyname='sel_project_commits_anon'
  ) THEN
    CREATE POLICY sel_project_commits_anon ON public.project_commits FOR SELECT TO postgrest_anon USING (true);
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_policies WHERE schemaname='public' AND tablename='project_contributors' AND policyname='all_project_contributors_app'
  ) THEN
    CREATE POLICY all_project_contributors_app ON public.project_contributors FOR ALL TO app USING (true) WITH CHECK (true);
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_policies WHERE schemaname='public' AND tablename='project_commits' AND policyname='all_project_commits_app'
  ) THEN
    CREATE POLICY all_project_commits_app ON public.project_commits FOR ALL TO app USING (true) WITH CHECK (true);
  END IF;
END $$;

-- API views
CREATE OR REPLACE VIEW api.project_contributors AS
  SELECT api_id AS id, id AS uuid, project_id, gh_user_id, login, display_name, email, commits_count,
         first_commit_at, last_commit_at, lines_added, lines_deleted, is_bot, risk_score, created_at
  FROM public.project_contributors;

CREATE OR REPLACE VIEW api.project_commits AS
  SELECT api_id AS id, id AS uuid, project_id, sha, author_login, author_email, committed_at,
         additions, deletions, files_changed, message, url, created_at
  FROM public.project_commits;

GRANT SELECT ON api.project_contributors, api.project_commits TO postgrest_anon;

-- RPC: upsert contributors
CREATE OR REPLACE FUNCTION api.upsert_project_contributors(
  p_project_id bigint,
  p_payload jsonb
)
RETURNS SETOF api.project_contributors
LANGUAGE sql
SECURITY DEFINER
SET search_path = public
AS $$
  WITH proj AS (
    SELECT id FROM public.projects WHERE api_id = p_project_id
  ), ins AS (
    INSERT INTO public.project_contributors (project_id, gh_user_id, login, display_name, email, commits_count,
                                            first_commit_at, last_commit_at, lines_added, lines_deleted, is_bot, risk_score)
    SELECT (SELECT id FROM proj),
           (x->>'gh_user_id')::bigint,
           x->>'login',
           x->>'display_name',
           x->>'email',
           COALESCE((x->>'commits_count')::int, 0),
           (x->>'first_commit_at')::timestamptz,
           (x->>'last_commit_at')::timestamptz,
           COALESCE((x->>'lines_added')::int, 0),
           COALESCE((x->>'lines_deleted')::int, 0),
           COALESCE((x->>'is_bot')::boolean, false),
           (x->>'risk_score')::numeric
    FROM jsonb_array_elements(p_payload) AS x
    ON CONFLICT (project_id, login)
    DO UPDATE SET gh_user_id = EXCLUDED.gh_user_id,
                  display_name = EXCLUDED.display_name,
                  email = EXCLUDED.email,
                  commits_count = EXCLUDED.commits_count,
                  first_commit_at = EXCLUDED.first_commit_at,
                  last_commit_at = EXCLUDED.last_commit_at,
                  lines_added = EXCLUDED.lines_added,
                  lines_deleted = EXCLUDED.lines_deleted,
                  is_bot = EXCLUDED.is_bot,
                  risk_score = EXCLUDED.risk_score,
                  updated_at = now()
    WHERE public.project_contributors.gh_user_id IS DISTINCT FROM EXCLUDED.gh_user_id
       OR public.project_contributors.display_name IS DISTINCT FROM EXCLUDED.display_name
       OR public.project_contributors.email IS DISTINCT FROM EXCLUDED.email
       OR public.project_contributors.commits_count IS DISTINCT FROM EXCLUDED.commits_count
       OR public.project_contributors.first_commit_at IS DISTINCT FROM EXCLUDED.first_commit_at
       OR public.project_contributors.last_commit_at IS DISTINCT FROM EXCLUDED.last_commit_at
       OR public.project_contributors.lines_added IS DISTINCT FROM EXCLUDED.lines_added
       OR public.project_contributors.lines_deleted IS DISTINCT FROM EXCLUDED.lines_deleted
       OR public.project_contributors.is_bot IS DISTINCT FROM EXCLUDED.is_bot
       OR public.project_contributors.risk_score IS DISTINCT FROM EXCLUDED.risk_score
    RETURNING *
  )
  SELECT api_id AS id, id AS uuid, project_id, gh_user_id, login, display_name, email, commits_count,
         first_commit_at, last_commit_at, lines_added, lines_deleted, is_bot, risk_score, created_at
    FROM ins;
$$;

GRANT EXECUTE ON FUNCTION api.upsert_project_contributors(bigint, jsonb) TO postgrest_anon;

-- RPC: upsert commits
CREATE OR REPLACE FUNCTION api.upsert_project_commits(
  p_project_id bigint,
  p_payload jsonb
)
RETURNS SETOF api.project_commits
LANGUAGE sql
SECURITY DEFINER
SET search_path = public
AS $$
  WITH proj AS (
    SELECT id FROM public.projects WHERE api_id = p_project_id
  ), ins AS (
    INSERT INTO public.project_commits (project_id, sha, author_login, author_email, committed_at, additions,
                                        deletions, files_changed, message, url)
    SELECT (SELECT id FROM proj),
           x->>'sha',
           x->>'author_login',
           x->>'author_email',
           (x->>'committed_at')::timestamptz,
           (x->>'additions')::int,
           (x->>'deletions')::int,
           (x->>'files_changed')::int,
           x->>'message',
           x->>'url'
    FROM jsonb_array_elements(p_payload) AS x
    ON CONFLICT (project_id, sha)
    DO UPDATE SET author_login = EXCLUDED.author_login,
                  author_email = EXCLUDED.author_email,
                  committed_at = EXCLUDED.committed_at,
                  additions = EXCLUDED.additions,
                  deletions = EXCLUDED.deletions,
                  files_changed = EXCLUDED.files_changed,
                  message = EXCLUDED.message,
                  url = EXCLUDED.url,
                  updated_at = now()
    WHERE public.project_commits.author_login IS DISTINCT FROM EXCLUDED.author_login
       OR public.project_commits.author_email IS DISTINCT FROM EXCLUDED.author_email
       OR public.project_commits.committed_at IS DISTINCT FROM EXCLUDED.committed_at
       OR public.project_commits.additions IS DISTINCT FROM EXCLUDED.additions
       OR public.project_commits.deletions IS DISTINCT FROM EXCLUDED.deletions
       OR public.project_commits.files_changed IS DISTINCT FROM EXCLUDED.files_changed
       OR public.project_commits.message IS DISTINCT FROM EXCLUDED.message
       OR public.project_commits.url IS DISTINCT FROM EXCLUDED.url
    RETURNING *
  )
  SELECT api_id AS id, id AS uuid, project_id, sha, author_login, author_email, committed_at,
         additions, deletions, files_changed, message, url, created_at
    FROM ins;
$$;

GRANT EXECUTE ON FUNCTION api.upsert_project_commits(bigint, jsonb) TO postgrest_anon;

-- RPC: update project stats (contributors_count, last_commit_at) via api_id
CREATE OR REPLACE FUNCTION api.update_project_stats(
  p_project_id bigint,
  p_stats jsonb
)
RETURNS TABLE (
  id bigint,
  uuid uuid,
  name text,
  repo_url text,
  description text,
  is_active boolean,
  created_at timestamptz
)
LANGUAGE sql
SECURITY DEFINER
SET search_path = public
AS $$
  WITH proj AS (
    SELECT id FROM public.projects WHERE api_id = p_project_id
  ), upd AS (
    UPDATE public.projects p SET
      contributors_count = COALESCE((p_stats->>'contributors_count')::int, p.contributors_count),
      last_commit_at = COALESCE((p_stats->>'last_commit_at')::timestamptz, p.last_commit_at),
      updated_at = now()
    WHERE p.id = (SELECT id FROM proj)
      AND (p.contributors_count IS DISTINCT FROM (p_stats->>'contributors_count')::int
        OR p.last_commit_at IS DISTINCT FROM (p_stats->>'last_commit_at')::timestamptz)
    RETURNING p.*
  )
  SELECT api_id, id, name, repo_url, description, is_active, created_at FROM upd
  UNION ALL
  SELECT api_id, id, name, repo_url, description, is_active, created_at FROM public.projects WHERE id = (SELECT id FROM proj) AND NOT EXISTS (SELECT 1 FROM upd);
$$;

GRANT EXECUTE ON FUNCTION api.update_project_stats(bigint, jsonb) TO postgrest_anon;
