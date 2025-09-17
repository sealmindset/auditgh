import { ROLES } from '../utils/constants.js';
import { config } from '../config/env.js';

export type RoleKey = keyof typeof ROLES;

export function mapGroupsToRoles(groups: string[] = []): RoleKey[] {
  const roles: RoleKey[] = [];
  if (!groups || groups.length === 0) return roles;
  const g = new Set(groups.map((x) => x.toLowerCase()));
  if (config.aadGroups.readonly && g.has(config.aadGroups.readonly.toLowerCase())) roles.push('reader');
  if (config.aadGroups.projectAdmin && g.has(config.aadGroups.projectAdmin.toLowerCase())) roles.push('project_admin');
  if (config.aadGroups.superAdmin && g.has(config.aadGroups.superAdmin.toLowerCase())) roles.push('super_admin');
  return Array.from(new Set(roles));
}
