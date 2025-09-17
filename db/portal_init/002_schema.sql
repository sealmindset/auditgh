-- Security Portal schema
CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = now();
  RETURN NEW;
END; $$ LANGUAGE plpgsql;

CREATE TABLE IF NOT EXISTS users (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  api_id bigserial UNIQUE NOT NULL,
  sub text UNIQUE NOT NULL,
  email text UNIQUE NOT NULL,
  display_name text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS roles (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  api_id bigserial UNIQUE NOT NULL,
  key text NOT NULL CHECK (key IN ('reader','project_admin','super_admin')),
  display_name text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE(key)
);

CREATE TABLE IF NOT EXISTS user_roles (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  api_id bigserial UNIQUE NOT NULL,
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role_id uuid NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE(user_id, role_id)
);

CREATE TABLE IF NOT EXISTS projects (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  api_id bigserial UNIQUE NOT NULL,
  name text NOT NULL UNIQUE,
  repo_url text,
  description text,
  is_active boolean NOT NULL DEFAULT true,
  created_by uuid REFERENCES users(id) ON DELETE SET NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS project_admins (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  api_id bigserial UNIQUE NOT NULL,
  project_id uuid NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE(project_id, user_id)
);

CREATE TABLE IF NOT EXISTS scans (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  api_id bigserial UNIQUE NOT NULL,
  project_id uuid NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  profile text,
  status text NOT NULL CHECK (status IN ('queued','running','success','failed','canceled')),
  started_at timestamptz,
  finished_at timestamptz,
  summary_md_path text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS scan_artifacts (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  api_id bigserial UNIQUE NOT NULL,
  scan_id uuid NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  name text NOT NULL,
  path text NOT NULL,
  mime text,
  size_bytes bigint,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS findings (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  api_id bigserial UNIQUE NOT NULL,
  project_id uuid NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  scan_id uuid REFERENCES scans(id) ON DELETE SET NULL,
  source text NOT NULL CHECK (source IN ('gitleaks','codeql','oss','terraform','cicd','binaries','linecount','custom')),
  rule_id text,
  title text NOT NULL,
  description text,
  severity text NOT NULL CHECK (severity IN ('critical','high','medium','low','info')),
  status text NOT NULL DEFAULT 'open' CHECK (status IN ('open','triaged','accepted','risk_accepted','remediated','duplicate','false_positive')),
  location jsonb,
  cwe text,
  kev_id text,
  epss_score numeric,
  tags text[] DEFAULT ARRAY[]::text[],
  metadata jsonb DEFAULT '{}'::jsonb,
  embedding vector(1536),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS integrations (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  api_id bigserial UNIQUE NOT NULL,
  type text NOT NULL CHECK (type IN ('github','slack','jira','custom')),
  name text NOT NULL,
  config jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

-- Updated_at triggers
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'users_set_updated_at') THEN
    CREATE TRIGGER users_set_updated_at BEFORE UPDATE ON users FOR EACH ROW EXECUTE PROCEDURE set_updated_at();
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'roles_set_updated_at') THEN
    CREATE TRIGGER roles_set_updated_at BEFORE UPDATE ON roles FOR EACH ROW EXECUTE PROCEDURE set_updated_at();
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'user_roles_set_updated_at') THEN
    CREATE TRIGGER user_roles_set_updated_at BEFORE UPDATE ON user_roles FOR EACH ROW EXECUTE PROCEDURE set_updated_at();
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'projects_set_updated_at') THEN
    CREATE TRIGGER projects_set_updated_at BEFORE UPDATE ON projects FOR EACH ROW EXECUTE PROCEDURE set_updated_at();
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'project_admins_set_updated_at') THEN
    CREATE TRIGGER project_admins_set_updated_at BEFORE UPDATE ON project_admins FOR EACH ROW EXECUTE PROCEDURE set_updated_at();
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'scans_set_updated_at') THEN
    CREATE TRIGGER scans_set_updated_at BEFORE UPDATE ON scans FOR EACH ROW EXECUTE PROCEDURE set_updated_at();
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'scan_artifacts_set_updated_at') THEN
    CREATE TRIGGER scan_artifacts_set_updated_at BEFORE UPDATE ON scan_artifacts FOR EACH ROW EXECUTE PROCEDURE set_updated_at();
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'findings_set_updated_at') THEN
    CREATE TRIGGER findings_set_updated_at BEFORE UPDATE ON findings FOR EACH ROW EXECUTE PROCEDURE set_updated_at();
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'integrations_set_updated_at') THEN
    CREATE TRIGGER integrations_set_updated_at BEFORE UPDATE ON integrations FOR EACH ROW EXECUTE PROCEDURE set_updated_at();
  END IF;
END $$;
