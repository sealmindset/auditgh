INSERT INTO roles (key, display_name) VALUES
  ('reader','Reader'),
  ('project_admin','Project Admin'),
  ('super_admin','Super Admin')
ON CONFLICT (key) DO NOTHING;

INSERT INTO users (sub, email, display_name)
VALUES ('dev-superadmin','dev@example.com','Dev SuperAdmin')
ON CONFLICT (email) DO NOTHING;

INSERT INTO user_roles (user_id, role_id)
SELECT u.id, r.id FROM users u, roles r
WHERE u.email = 'dev@example.com' AND r.key = 'super_admin'
ON CONFLICT DO NOTHING;

INSERT INTO projects (name, repo_url, description)
VALUES ('demo-project','https://github.com/example/demo','Demo project')
ON CONFLICT (name) DO NOTHING;
