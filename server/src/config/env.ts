import 'dotenv/config';

export type AppConfig = {
  nodeEnv: string;
  port: number;
  sessionSecret: string;
  authDisabled: boolean;

  // OIDC
  oidc: {
    issuer: string | undefined;
    tenantId: string | undefined;
    clientId: string | undefined;
    clientSecret: string | undefined;
    redirectUri: string | undefined;
  };

  // AAD group mapping
  aadGroups: {
    readonly: string | undefined;
    projectAdmin: string | undefined;
    superAdmin: string | undefined;
  };

  // Infra
  databaseUrl: string;
  redisUrl: string | undefined;

  // Orchestration
  auditWorkspaceDir: string;

  // Vector size
  vectorDim: number;

  // PostgREST
  postgrestJwtSecret: string | undefined;
};

export const config: AppConfig = {
  nodeEnv: process.env.NODE_ENV || 'development',
  port: parseInt(process.env.PORT || '8080', 10),
  sessionSecret: process.env.SESSION_SECRET || 'change-me',
  authDisabled: (process.env.AUTH_DISABLED || 'false').toLowerCase() === 'true',
  oidc: {
    issuer: process.env.OIDC_ISSUER,
    tenantId: process.env.OIDC_TENANT_ID,
    clientId: process.env.OIDC_CLIENT_ID,
    clientSecret: process.env.OIDC_CLIENT_SECRET,
    redirectUri: process.env.OIDC_REDIRECT_URI,
  },
  aadGroups: {
    readonly: process.env.AAD_GROUP_READONLY,
    projectAdmin: process.env.AAD_GROUP_PROJECT_ADMIN,
    superAdmin: process.env.AAD_GROUP_SUPERADMIN,
  },
  databaseUrl: process.env.DATABASE_URL || 'postgres://postgres:postgres@localhost:5432/security_portal',
  redisUrl: process.env.REDIS_URL,
  auditWorkspaceDir: process.env.AUDIT_WORKSPACE_DIR || './runs',
  vectorDim: parseInt(process.env.VECTOR_DIM || '1536', 10),
  postgrestJwtSecret: process.env.POSTGREST_JWT_SECRET,
};
