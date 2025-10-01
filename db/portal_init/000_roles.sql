-- 000_roles.sql
-- Ensure core roles exist for PostgREST and application policies on first init
-- Idempotent: safe on subsequent starts

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'app') THEN
    CREATE ROLE app LOGIN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'postgrest_anon') THEN
    CREATE ROLE postgrest_anon NOLOGIN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'postgrest_service') THEN
    CREATE ROLE postgrest_service NOLOGIN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'postgrest_admin') THEN
    CREATE ROLE postgrest_admin NOLOGIN;
  END IF;
END $$;
