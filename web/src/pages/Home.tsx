import { useEffect, useMemo, useState } from 'react'
import { xhrGetJson } from '../lib/xhr'
import DataTable, { type ColumnDef } from '../components/DataTable'

export default function Home() {
  const base = useMemo(() => window.location.origin, [])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string|null>(null)
  const [summary, setSummary] = useState<{ severity_totals: any; projects_count: number; repos_count: number; scans_count: number } | null>(null)
  const [topRepos, setTopRepos] = useState<any[]>([])
  const [recentScans, setRecentScans] = useState<any[]>([])
  // Phase 1 additions
  const [projects, setProjects] = useState<any[]>([])
  const [recentCommits, setRecentCommits] = useState<any[]>([])

  useEffect(() => {
    async function load() {
      setLoading(true)
      setError(null)
      try {
        const [sum, tops, scans] = await Promise.all([
          xhrGetJson(`${base}/api/dashboard/summary`),
          xhrGetJson(`${base}/api/dashboard/top-repos?limit=10`),
          xhrGetJson(`${base}/api/dashboard/recent-scans?limit=10`),
        ])
        setSummary(sum?.data || null)
        setTopRepos(tops?.data || [])
        setRecentScans(scans?.data || [])
        // Repository overview (basic): pull from PostgREST projects
        const projRows = await xhrGetJson(`${base}/db/projects?select=uuid,name,repo_url,primary_language,contributors_count,last_commit_at&order=name.asc`)
        setProjects(projRows || [])
        // Recent commits (org-wide): limited to latest 500 for charts/top contributors
        const commitRows = await xhrGetJson(`${base}/db/project_commits?select=author_login,committed_at&order=committed_at.desc&limit=500`)
        setRecentCommits(commitRows || [])
      } catch (e: any) {
        setError(e?.message || 'Failed to load dashboard')
      } finally {
        setLoading(false)
      }
    }
    // Fire and forget
    // eslint-disable-next-line @typescript-eslint/no-floating-promises
    load()
  }, [base])

  const sev = summary?.severity_totals || { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0, unknown: 0 }
  const sevTotal = Number(sev.total || (sev.critical + sev.high + sev.medium + sev.low + sev.info + sev.unknown) || 0)

  // Derived: Findings trend (per day) from recentScans
  const findingsTrend = useMemo(() => {
    const map = new Map<string, number>()
    for (const s of recentScans || []) {
      const d = s.finished_at ? new Date(s.finished_at) : null
      if (!d) continue
      const key = d.toISOString().slice(0,10)
      map.set(key, (map.get(key) || 0) + Number(s.findings_count || 0))
    }
    const entries = Array.from(map.entries()).sort(([a],[b]) => a.localeCompare(b))
    return entries
  }, [recentScans])

  // Derived: Commits trend and Top Contributors from recentCommits
  const commitsTrend = useMemo(() => {
    const map = new Map<string, number>()
    for (const c of recentCommits || []) {
      const d = c.committed_at ? new Date(c.committed_at) : null
      if (!d) continue
      const key = d.toISOString().slice(0,10)
      map.set(key, (map.get(key) || 0) + 1)
    }
    const entries = Array.from(map.entries()).sort(([a],[b]) => a.localeCompare(b))
    return entries
  }, [recentCommits])

  const topContributors = useMemo(() => {
    const counts = new Map<string, number>()
    for (const c of recentCommits || []) {
      const k = String(c.author_login || '').trim() || '(unknown)'
      counts.set(k, (counts.get(k) || 0) + 1)
    }
    return Array.from(counts.entries()).map(([login, commits]) => ({ login, commits })).sort((a,b) => b.commits - a.commits).slice(0, 50)
  }, [recentCommits])

  // Helpers: repo short extraction and matching to projects
  function repoShortFromUrl(url: string | null | undefined): string {
    if (!url) return ''
    const raw = String(url).trim()
    // ssh: git@host:owner/repo(.git)
    const m1 = /^git@[^:]+:([^\s]+)$/i.exec(raw)
    if (m1) return (m1[1].split('/').pop() || '').replace(/\.git$/i, '').toLowerCase()
    // plain owner/repo(.git)
    if (!raw.includes('://') && raw.includes('/')) return (raw.split('/').pop() || '').replace(/\.git$/i, '').toLowerCase()
    // http(s)
    try {
      const u = new URL(raw)
      return (u.pathname.replace(/^\//,'').split('/').pop() || '').replace(/\.git$/i, '').toLowerCase()
    } catch { return '' }
  }

  function normalizeRepoKey(s: string): string { return (s || '').toLowerCase().replace(/[^a-z0-9]+/g, '') }

  function findProjectByRepoShort(repoShort: string): any | null {
    const target = (repoShort || '').toLowerCase()
    if (!target) return null
    const norm = normalizeRepoKey(target)
    // 1) exact match on short
    const projExact = (projects || []).find((p) => repoShortFromUrl(p.repo_url) === target)
    if (projExact) return projExact
    // 2) normalized equality only (avoid containment to prevent false positives)
    if (!norm) return null
    const projNorm = (projects || []).find((p) => normalizeRepoKey(repoShortFromUrl(p.repo_url)) === norm)
    return projNorm || null
  }

  // Inline SVG helpers for trend lines
  function TrendSvg({ data, stroke, height=60 }: { data: [string, number][], stroke: string, height?: number }) {
    const padding = 4
    const w = 240
    const h = height
    const vals = data.map(([,v]) => Number(v || 0))
    const max = Math.max(1, ...vals)
    const pts = data.map(([,v], i) => {
      const x = padding + (i * (w - padding*2)) / Math.max(1, data.length - 1)
      const y = h - padding - (Number(v||0) / max) * (h - padding*2)
      return `${x},${y}`
    }).join(' ')
    return (
      <svg width={w} height={h} className="border rounded bg-white">
        <polyline fill="none" stroke={stroke} strokeWidth="2" points={pts} />
      </svg>
    )
  }

  return (
    <div className="min-h-screen bg-slate-50">
      <main className="max-w-screen-2xl mx-auto px-4 py-4 space-y-4">
        <h1 className="text-xl font-semibold">Home</h1>
        {loading ? (
          <div className="text-sm text-slate-600">Loading…</div>
        ) : error ? (
          <div className="text-sm text-red-700">{error}</div>
        ) : (
          <>
            <section>
              <div className="grid grid-cols-2 md:grid-cols-6 gap-3">
                {[
                  { label: 'Total', value: sev.total, cls: 'bg-slate-100' },
                  { label: 'Critical', value: sev.critical, cls: 'bg-red-600 text-white' },
                  { label: 'High', value: sev.high, cls: 'bg-red-500 text-white' },
                  { label: 'Medium', value: sev.medium, cls: 'bg-amber-400 text-black' },
                  { label: 'Low', value: sev.low, cls: 'bg-yellow-200 text-black' },
                  { label: 'Info', value: sev.info, cls: 'bg-blue-200 text-black' },
                ].map((c, i) => (
                  <div key={i} className={`rounded border border-slate-200 p-3 ${c.cls}`}>
                    <div className="text-xs uppercase tracking-wide">{c.label}</div>
                    <div className="text-2xl font-semibold">{Number(c.value || 0).toLocaleString()}</div>
                  </div>
                ))}
              </div>
              <div className="grid grid-cols-2 md:grid-cols-3 gap-3 mt-3">
                <div className="rounded border bg-white p-3">
                  <div className="text-xs text-slate-500">Projects</div>
                  <div className="text-xl font-semibold">{Number(summary?.projects_count || 0).toLocaleString()}</div>
                </div>
                <div className="rounded border bg-white p-3">
                  <div className="text-xs text-slate-500">CodeQL Scanned</div>
                  <div className="text-xl font-semibold">{Number(summary?.repos_count || 0).toLocaleString()}</div>
                </div>
                <div className="rounded border bg-white p-3">
                  <div className="text-xs text-slate-500">Scans</div>
                  <div className="text-xl font-semibold">{Number(summary?.scans_count || 0).toLocaleString()}</div>
                </div>
              </div>
            </section>

            <section className="bg-white p-4 rounded border">
              <div className="flex items-center justify-between mb-2">
                <h2 className="font-medium">Top CodeQL Repositories</h2>
                <a href="/projects" className="text-blue-600 underline text-sm">View Projects</a>
              </div>
              {(() => {
                const columns: ColumnDef<any>[] = [
                  { key: 'repo', header: 'Repository', render: (r) => {
                    const proj = findProjectByRepoShort(r.repo)
                    return proj ? (
                      <a className="text-blue-600 underline" href={`/projects/${proj.uuid}`}>{r.repo}</a>
                    ) : (
                      <span>{r.repo}</span>
                    )
                  } },
                  { key: 'critical', header: 'Critical', widthClass: 'w-24' },
                  { key: 'high', header: 'High', widthClass: 'w-24' },
                  { key: 'medium', header: 'Medium', widthClass: 'w-24' },
                  { key: 'low', header: 'Low', widthClass: 'w-24' },
                  { key: 'info', header: 'Info', widthClass: 'w-24' },
                  { key: 'total', header: 'Total', widthClass: 'w-28' },
                ]
                return (
                  <DataTable
                    data={topRepos}
                    columns={columns}
                    defaultPageSize={10}
                    pageSizeOptions={[10,25,50]}
                    searchPlaceholder="Search repositories…"
                    filterKeys={['repo']}
                  />
                )
              })()}
            </section>

            <section className="bg-white p-4 rounded border">
              <div className="flex items-center justify-between mb-2">
                <h2 className="font-medium">Repository Overview</h2>
                <a href="/projects" className="text-blue-600 underline text-sm">Manage Projects</a>
              </div>
              {(() => {
                const rows = (projects || []).map((p: any) => {
                  let owner = ''
                  try { const u = new URL(p.repo_url || ''); const parts = u.pathname.replace(/^\//,'').split('/'); owner = parts[0] || '' } catch {}
                  return {
                    uuid: p.uuid,
                    name: p.name,
                    owner,
                    primary_language: p.primary_language || '—',
                    last_commit_at: p.last_commit_at || null,
                    contributors_count: p.contributors_count ?? 0,
                    license: '—',
                  }
                })
                const columns: ColumnDef<any>[] = [
                  { key: 'name', header: 'Repository', render: (r) => <a className="text-blue-600 underline" href={`/projects/${r.uuid}`}>{r.name}</a> },
                  { key: 'owner', header: 'Owner' },
                  { key: 'primary_language', header: 'Primary Language' },
                  { key: 'last_commit_at', header: 'Last Commit', render: (r) => r.last_commit_at ? new Date(r.last_commit_at).toLocaleString() : '—' },
                  { key: 'contributors_count', header: 'Contributors' },
                  { key: 'license', header: 'License' },
                ]
                return (
                  <DataTable
                    data={rows}
                    columns={columns}
                    defaultPageSize={10}
                    pageSizeOptions={[10,25,50]}
                    filterKeys={['name','owner','primary_language','license']}
                    searchPlaceholder="Search repositories…"
                  />
                )
              })()}
            </section>

            <section className="bg-white p-4 rounded border">
              <div className="flex items-center justify-between mb-2">
                <h2 className="font-medium">Security Alerts (CodeQL)</h2>
                <div className="text-xs text-slate-600">Org totals severity distribution</div>
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                <div>
                  <div className="text-xs text-slate-600 mb-1">Severity Distribution</div>
                  <div className="space-y-1">
                    {[
                      ['Critical','bg-red-600 text-white', Number(sev.critical||0)],
                      ['High','bg-red-500 text-white', Number(sev.high||0)],
                      ['Medium','bg-amber-400 text-black', Number(sev.medium||0)],
                      ['Low','bg-yellow-200 text-black', Number(sev.low||0)],
                      ['Info','bg-blue-200 text-black', Number(sev.info||0)],
                      ['Unknown','bg-slate-200 text-black', Number(sev.unknown||0)],
                    ].map(([label, cls, val], idx) => {
                      const pct = sevTotal > 0 ? Math.max(2, Math.round((val as number) * 100 / sevTotal)) : 0
                      return (
                        <div key={idx} className="flex items-center gap-2 text-xs">
                          <div className="w-20 text-right">{label}</div>
                          <div className="flex-1 h-4 bg-slate-100 rounded">
                            <div className={`h-4 rounded ${cls as string}`} style={{ width: `${pct}%` }} title={`${val} (${pct}%)`} />
                          </div>
                          <div className="w-16 text-right">{Number(val).toLocaleString()}</div>
                        </div>
                      )
                    })}
                  </div>
                </div>
                <div>
                  <div className="text-xs text-slate-600 mb-1">Findings Trend (recent scans)</div>
                  <TrendSvg data={findingsTrend} stroke="#0ea5e9" />
                </div>
              </div>
            </section>

            <section className="bg-white p-4 rounded border">
              <div className="flex items-center justify-between mb-2">
                <h2 className="font-medium">Contributor & Activity</h2>
                <div className="text-xs text-slate-600">Last ~500 commits (org-wide)</div>
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                <div>
                  <div className="text-xs text-slate-600 mb-1">Recent Commits Trend</div>
                  <TrendSvg data={commitsTrend} stroke="#10b981" />
                </div>
                <div>
                  <div className="text-xs text-slate-600 mb-1">Top Contributors</div>
                  {(() => {
                    const columns: ColumnDef<any>[] = [
                      { key: 'login', header: 'Login' },
                      { key: 'commits', header: 'Commits' },
                    ]
                    return (
                      <DataTable
                        data={topContributors}
                        columns={columns}
                        defaultPageSize={10}
                        pageSizeOptions={[10,25,50]}
                        filterKeys={['login']}
                        searchPlaceholder="Search contributors…"
                      />
                    )
                  })()}
                </div>
              </div>
            </section>

            <section className="bg-white p-4 rounded border">
              <div className="flex items-center justify-between mb-2">
                <h2 className="font-medium">Recent Scans</h2>
                <a href="/scans" className="text-blue-600 underline text-sm">View Scans</a>
              </div>
              {(() => {
                const columns: ColumnDef<any>[] = [
                  { key: 'project_name', header: 'Project', render: (s) => <a className="text-blue-600 underline" href={`/projects/${s.project_id}`}>{s.project_name}</a> },
                  { key: 'profile', header: 'Profile' },
                  { key: 'status', header: 'Status' },
                  { key: 'finished_at', header: 'Finished', render: (s) => (s.finished_at ? new Date(s.finished_at).toLocaleString() : '—') },
                  { key: 'findings_count', header: 'Findings', widthClass: 'w-28' },
                  { key: 'repositories', header: 'Repos', widthClass: 'w-24' },
                ]
                return (
                  <DataTable
                    data={recentScans}
                    columns={columns}
                    defaultPageSize={10}
                    pageSizeOptions={[10,25,50]}
                    searchPlaceholder="Search recent scans…"
                    filterKeys={['project_name','profile','status']}
                  />
                )
              })()}
            </section>
          </>
        )}
      </main>
    </div>
  )
}
