export const ROLES = {
  reader: 'reader',
  project_admin: 'project_admin',
  super_admin: 'super_admin',
} as const;

export type RoleKey = keyof typeof ROLES;
