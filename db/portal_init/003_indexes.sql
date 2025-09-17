CREATE INDEX IF NOT EXISTS idx_projects_active ON projects(is_active);
CREATE INDEX IF NOT EXISTS idx_scans_project ON scans(project_id);
CREATE INDEX IF NOT EXISTS idx_findings_project ON findings(project_id);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
CREATE INDEX IF NOT EXISTS idx_findings_tags ON findings USING GIN (tags);
CREATE INDEX IF NOT EXISTS idx_findings_metadata ON findings USING GIN (metadata);
CREATE INDEX IF NOT EXISTS idx_findings_embedding ON findings USING ivfflat (embedding vector_l2_ops) WITH (lists = 100);
