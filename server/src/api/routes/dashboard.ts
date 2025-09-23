import { Router } from 'express';
import { requireAuth } from '../../auth/middleware.js';
import { pool } from '../../db/pool.js';

export const dashboardRouter = Router();

// Org-wide summary KPIs
// - severity_totals from api.codeql_org_severity_totals
// - projects_count from projects
// - repos_count from codeql_scan_repos distinct repo_short
// - scans_count from scans

dashboardRouter.get('/summary', requireAuth, async (_req, res, next) => {
  try {
    const [{ rows: sevRows }, { rows: projRows }, { rows: repoRows }, { rows: scanRows }] = await Promise.all([
      pool.query(`with last_success as (
                    select s.project_id, max(s.finished_at) as max_finished
                    from public.scans s
                    where s.status = 'success'
                    group by s.project_id
                  ), latest_scans as (
                    select s.id
                    from public.scans s
                    join last_success m on m.project_id = s.project_id and m.max_finished = s.finished_at
                    where s.status = 'success'
                  ), cq as (
                    select lower(cf.severity) as severity, count(*)::int as cnt
                    from public.codeql_findings cf
                    join latest_scans ls on ls.id = cf.scan_id
                    group by lower(cf.severity)
                  ), os as (
                    select lower(f.severity) as severity, count(*)::int as cnt
                    from public.findings f
                    join latest_scans ls on ls.id = f.scan_id
                    where f.source = 'oss'
                    group by lower(f.severity)
                  ), agg as (
                    select severity, sum(cnt)::int as cnt from (
                      select * from cq
                      union all
                      select * from os
                    ) u group by severity
                  )
                  select
                    coalesce(sum(cnt),0)::int as total,
                    coalesce(sum(case when severity = 'critical' then cnt end),0)::int as critical,
                    coalesce(sum(case when severity = 'high' then cnt end),0)::int as high,
                    coalesce(sum(case when severity = 'medium' then cnt end),0)::int as medium,
                    coalesce(sum(case when severity = 'low' then cnt end),0)::int as low,
                    coalesce(sum(case when severity = 'info' then cnt end),0)::int as info,
                    coalesce(sum(case when severity not in ('critical','high','medium','low','info') then cnt end),0)::int as unknown
                  from agg`),
      pool.query('select count(*)::int as count from projects where is_active = true'),
      pool.query(`with last_success as (
                    select s.project_id, max(s.finished_at) as max_finished
                    from public.scans s
                    where s.status = 'success'
                    group by s.project_id
                  ), latest_scans as (
                    select s.id
                    from public.scans s
                    join last_success m on m.project_id = s.project_id and m.max_finished = s.finished_at
                    where s.status = 'success'
                  )
                  select count(distinct lower(csr.repo_short)) as count
                  from public.codeql_scan_repos csr
                  join latest_scans ls on ls.id = csr.scan_id`),
      pool.query('select count(*)::int as count from scans'),
    ]);
    const severity_totals = sevRows[0] || { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0, unknown: 0 };
    const projects_count = projRows[0]?.count || 0;
    const repos_count = repoRows[0]?.count || 0;
    const scans_count = scanRows[0]?.count || 0;
    res.json({ data: { severity_totals, projects_count, repos_count, scans_count } });
  } catch (err) { next(err); }
});

// Top repos by severity totals

dashboardRouter.get('/top-repos', requireAuth, async (req, res, next) => {
  try {
    const limit = Math.min(parseInt((req.query.limit as string) || '10', 10) || 10, 100);
    const { rows } = await pool.query(
      `with owner_map as (
         select
           p.id  as owner_project_id,
           p.name as owner_project_name,
           lower(
             regexp_replace(
               regexp_replace(trim(both from p.repo_url), '^.*/', ''),
               '\\.[Gg][Ii][Tt]$',
               ''
             )
           ) as repo_short
         from public.projects p
         where coalesce(nullif(btrim(p.repo_url), ''), '') <> ''
       ),
       last_success as (
         select s.project_id, max(s.finished_at) as max_finished
         from public.scans s
         where s.status = 'success'
         group by s.project_id
       ),
       latest_scans as (
         select s.id, s.project_id
         from public.scans s
         join last_success m on m.project_id = s.project_id and m.max_finished = s.finished_at
         where s.status = 'success'
       ),
       codeql as (
         select
           om.owner_project_id as project_id,
           om.owner_project_name as project_name,
           om.repo_short as repo,
           sum(case when lower(cf.severity) = 'critical' then 1 else 0 end)::int as critical,
           sum(case when lower(cf.severity) = 'high' then 1 else 0 end)::int as high,
           sum(case when lower(cf.severity) = 'medium' then 1 else 0 end)::int as medium,
           sum(case when lower(cf.severity) = 'low' then 1 else 0 end)::int as low,
           sum(case when lower(cf.severity) = 'info' then 1 else 0 end)::int as info,
           count(*)::int as total
         from owner_map om
         join latest_scans ls on ls.project_id = om.owner_project_id
         join public.codeql_findings cf on cf.scan_id = ls.id and lower(cf.repo_short) = om.repo_short
         group by om.owner_project_id, om.owner_project_name, om.repo_short
       ),
       oss as (
         select
           om.owner_project_id as project_id,
           om.owner_project_name as project_name,
           om.repo_short as repo,
           sum(case when lower(f.severity) = 'critical' then 1 else 0 end)::int as critical,
           sum(case when lower(f.severity) = 'high' then 1 else 0 end)::int as high,
           sum(case when lower(f.severity) = 'medium' then 1 else 0 end)::int as medium,
           sum(case when lower(f.severity) = 'low' then 1 else 0 end)::int as low,
           sum(case when lower(f.severity) = 'info' then 1 else 0 end)::int as info,
           count(*)::int as total
         from owner_map om
         join latest_scans ls on ls.project_id = om.owner_project_id
         join public.findings f on f.scan_id = ls.id and f.source = 'oss' and lower(coalesce(f.metadata->>'repo_short','')) = om.repo_short
         group by om.owner_project_id, om.owner_project_name, om.repo_short
       )
       select
         project_id,
         project_name,
         repo,
         coalesce(sum(critical),0)::int as critical,
         coalesce(sum(high),0)::int as high,
         coalesce(sum(medium),0)::int as medium,
         coalesce(sum(low),0)::int as low,
         coalesce(sum(info),0)::int as info,
         coalesce(sum(total),0)::int as total
       from (
         select * from codeql
         union all
         select * from oss
       ) u
       group by project_id, project_name, repo
       order by critical desc, high desc, total desc
       limit $1`,
      [limit]
    );
    res.json({ data: rows });
  } catch (err) { next(err); }
});

// Recent scans summary

dashboardRouter.get('/recent-scans', requireAuth, async (req, res, next) => {
  try {
    const limit = Math.min(parseInt((req.query.limit as string) || '10', 10) || 10, 100);
    const { rows } = await pool.query(
      `select scan_id, project_id, project_name, profile, status, finished_at, findings_count, repositories
       from api.codeql_recent_scans
       where status in ('success','failed')
       order by finished_at desc nulls last
       limit $1`,
      [limit]
    );
    res.json({ data: rows });
  } catch (err) { next(err); }
});
