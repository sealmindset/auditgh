-- OSS findings support indexes
-- Create expression index to speed lookups by repo short for OSS entries
-- Safe to run multiple times
DO $$ BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_indexes WHERE schemaname = 'public' AND indexname = 'findings_oss_repo_idx'
  ) THEN
    CREATE INDEX findings_oss_repo_idx
      ON public.findings ((lower((metadata->>'repo_short'))))
      WHERE source = 'oss';
  END IF;
END $$;
