import { z } from 'zod';

export const scannerNames = [
  'cicd',
  'gitleaks',
  'hardcoded_ips',
  'oss',
  'terraform',
  'codeql',
  'contributors',
  'binaries',
  'linecount',
] as const;

export const createScanSchema = z.object({
  project_id: z.string().uuid(),
  profile: z.string().min(1).max(128).optional(),
  scanners: z.array(z.enum(scannerNames)).min(1).optional(),
  scope: z.enum(['org', 'repo']).optional(),
  repo: z.string().min(1).max(200).optional(),
  codeql_languages: z.array(z.string()).optional(),
  codeql_skip_autobuild: z.boolean().optional(),
  codeql_recreate_db: z.boolean().optional(),
});

export type CreateScanInput = z.infer<typeof createScanSchema>;
