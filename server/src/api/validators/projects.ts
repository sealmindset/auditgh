import { z } from 'zod';

export const createProjectSchema = z.object({
  name: z.string().min(1).max(200),
  repo_url: z.string().url().optional().or(z.literal('')).transform((v) => v || null),
  description: z.string().max(2000).optional().or(z.literal('')).transform((v) => v || null),
});

export type CreateProjectInput = z.infer<typeof createProjectSchema>;
