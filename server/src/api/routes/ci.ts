import { Router } from 'express';
import { requireAuth } from '../../auth/middleware.js';

export const ciRouter = Router();

// GET /api/repo/:owner/:repo/actions/runs
// Proxies to GitHub Actions API and returns a lean list of workflow runs
ciRouter.get('/:owner/:repo/actions/runs', requireAuth, async (req, res) => {
  try {
    const owner = (req.params as any).owner as string;
    const repo = (req.params as any).repo as string;
    if (!owner || !repo) {
      return res.status(400).json({ error: { code: 'bad_request', message: 'owner and repo are required' } });
    }

    const ghToken = process.env.GITHUB_TOKEN || process.env.GH_TOKEN || '';
    if (!ghToken) {
      return res.status(500).json({ error: { code: 'missing_token', message: 'Server is missing GITHUB_TOKEN. Configure a GitHub token to enable CI/CD integration.' } });
    }

    const per_page = Math.min(parseInt((req.query.per_page as string) || '50', 10) || 50, 100);
    const status = (req.query.status as string) || undefined; // queued|in_progress|completed
    const conclusion = (req.query.conclusion as string) || undefined; // success|failure|cancelled|...
    const branch = (req.query.branch as string) || undefined;

    const params = new URLSearchParams();
    params.set('per_page', String(per_page));
    if (status) params.set('status', status);
    if (conclusion) params.set('conclusion', conclusion);
    if (branch) params.set('branch', branch);

    const url = `https://api.github.com/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/actions/runs?${params.toString()}`;
    const resp = await fetch(url, {
      headers: {
        'Accept': 'application/vnd.github+json',
        'Authorization': `Bearer ${ghToken}`,
        'X-GitHub-Api-Version': '2022-11-28',
        'User-Agent': 'auditgh-portal-ci-proxy'
      }
    });

    const text = await resp.text();
    if (!resp.ok) {
      return res.status(resp.status).json({ error: { code: 'github_error', message: text } });
    }
    let data: any;
    try { data = text ? JSON.parse(text) : {}; } catch { data = {}; }
    const items: any[] = Array.isArray(data?.workflow_runs) ? data.workflow_runs : [];

    const mapped = items.map((r) => ({
      id: r.id,
      run_number: r.run_number,
      name: r.name || r.display_title || '',
      event: r.event,
      status: r.status, // queued|in_progress|completed
      conclusion: r.conclusion, // success|failure|cancelled|...
      branch: r.head_branch,
      actor_login: r.actor?.login || '',
      commit_sha: r.head_sha || '',
      html_url: r.html_url,
      created_at: r.created_at,
      updated_at: r.updated_at,
      workflow_id: r.workflow_id,
      workflow_name: r.name || '',
    }));

    return res.json({ items: mapped });
  } catch (e: any) {
    return res.status(500).json({ error: { code: 'proxy_error', message: String(e?.message || e) } });
  }
});
