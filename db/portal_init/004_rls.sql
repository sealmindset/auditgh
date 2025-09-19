DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'app') THEN
    CREATE ROLE app LOGIN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'postgrest_anon') THEN
    CREATE ROLE postgrest_anon NOLOGIN;
  END IF;
END $$;

GRANT USAGE ON SCHEMA public TO app, postgrest_anon;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO postgrest_anon;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO app, postgrest_anon;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO app;

ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO postgrest_anon;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO app, postgrest_anon;

ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE roles ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_roles ENABLE ROW LEVEL SECURITY;
ALTER TABLE projects ENABLE ROW LEVEL SECURITY;
ALTER TABLE project_admins ENABLE ROW LEVEL SECURITY;
ALTER TABLE scans ENABLE ROW LEVEL SECURITY;
ALTER TABLE scan_artifacts ENABLE ROW LEVEL SECURITY;
ALTER TABLE findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE integrations ENABLE ROW LEVEL SECURITY;

DO $$ BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'users' AND policyname = 'sel_users_anon'
  ) THEN
    CREATE POLICY sel_users_anon ON users FOR SELECT TO postgrest_anon USING (true);
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'roles' AND policyname = 'sel_roles_anon'
  ) THEN
    CREATE POLICY sel_roles_anon ON roles FOR SELECT TO postgrest_anon USING (true);
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'user_roles' AND policyname = 'sel_user_roles_anon'
  ) THEN
    CREATE POLICY sel_user_roles_anon ON user_roles FOR SELECT TO postgrest_anon USING (true);
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'projects' AND policyname = 'sel_projects_anon'
  ) THEN
    CREATE POLICY sel_projects_anon ON projects FOR SELECT TO postgrest_anon USING (true);
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'project_admins' AND policyname = 'sel_project_admins_anon'
  ) THEN
    CREATE POLICY sel_project_admins_anon ON project_admins FOR SELECT TO postgrest_anon USING (true);
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'scans' AND policyname = 'sel_scans_anon'
  ) THEN
    CREATE POLICY sel_scans_anon ON scans FOR SELECT TO postgrest_anon USING (true);
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'scan_artifacts' AND policyname = 'sel_scan_artifacts_anon'
  ) THEN
    CREATE POLICY sel_scan_artifacts_anon ON scan_artifacts FOR SELECT TO postgrest_anon USING (true);
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'findings' AND policyname = 'sel_findings_anon'
  ) THEN
    CREATE POLICY sel_findings_anon ON findings FOR SELECT TO postgrest_anon USING (true);
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'integrations' AND policyname = 'sel_integrations_anon'
  ) THEN
    CREATE POLICY sel_integrations_anon ON integrations FOR SELECT TO postgrest_anon USING (true);
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'users' AND policyname = 'all_users_app'
  ) THEN
    CREATE POLICY all_users_app ON users FOR ALL TO app USING (true) WITH CHECK (true);
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'roles' AND policyname = 'all_roles_app'
  ) THEN
    CREATE POLICY all_roles_app ON roles FOR ALL TO app USING (true) WITH CHECK (true);
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'user_roles' AND policyname = 'all_user_roles_app'
  ) THEN
    CREATE POLICY all_user_roles_app ON user_roles FOR ALL TO app USING (true) WITH CHECK (true);
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'projects' AND policyname = 'all_projects_app'
  ) THEN
    CREATE POLICY all_projects_app ON projects FOR ALL TO app USING (true) WITH CHECK (true);
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'project_admins' AND policyname = 'all_project_admins_app'
  ) THEN
    CREATE POLICY all_project_admins_app ON project_admins FOR ALL TO app USING (true) WITH CHECK (true);
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'scans' AND policyname = 'all_scans_app'
  ) THEN
    CREATE POLICY all_scans_app ON scans FOR ALL TO app USING (true) WITH CHECK (true);
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'scan_artifacts' AND policyname = 'all_scan_artifacts_app'
  ) THEN
    CREATE POLICY all_scan_artifacts_app ON scan_artifacts FOR ALL TO app USING (true) WITH CHECK (true);
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'findings' AND policyname = 'all_findings_app'
  ) THEN
    CREATE POLICY all_findings_app ON findings FOR ALL TO app USING (true) WITH CHECK (true);
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'integrations' AND policyname = 'all_integrations_app'
  ) THEN
    CREATE POLICY all_integrations_app ON integrations FOR ALL TO app USING (true) WITH CHECK (true);
  END IF;
END $$;
