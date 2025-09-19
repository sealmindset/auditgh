import { useEffect, useMemo, useState } from 'react'
import { xhrGetJson, xhrPostJson } from '../lib/xhr'
import OssVulnTables from '../components/OssVulnTables'

export type ApiProject = { id: number; uuid: string; name: string; repo_url: string | null; description: string | null; is_active: boolean; created_at: string; updated_at?: string; contributors_count?: number; last_commit_at?: string | null; primary_language?: string | null; total_loc?: number }

function ownerRepoFromUrl(url: string | null): string | null {
  if (!url) return null
  try {
    const u = new URL(url)
    const parts = u.pathname.replace(/^\//,'').split('/')
    if (parts.length >= 2) return `${parts[0]}/${parts[1]}`
    return null
  } catch { return null }
}

export default function ProjectDetail({ uuid }: { uuid: string }) {
  const base = useMemo(() => window.location.origin, [])
  const [item, setItem] = useState<ApiProject | null>(null)
  const [form, setForm] = useState<{ name: string; repo_url: string; description: string; is_active: boolean } | null>(null)
  const [loading, setLoading] = useState(false)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)
  // Languages breakdown
  const [langs, setLangs] = useState<{ language: string; bytes: number; loc?: number; files?: number; is_primary: boolean }[]>([])
  const [loadingLangs, setLoadingLangs] = useState(false)
  const [errorLangs, setErrorLangs] = useState<string | null>(null)
  const [contributors, setContributors] = useState<{ login: string; display_name?: string | null; email?: string | null; commits_count?: number; last_commit_at?: string | null }[]>([])
  const [commits, setCommits] = useState<{ sha: string; author_login?: string | null; author_email?: string | null; committed_at: string; message?: string | null; url?: string | null }[]>([])
  const [loadingContrib, setLoadingContrib] = useState(false)
  const [loadingCommits, setLoadingCommits] = useState(false)
  const [errorContrib, setErrorContrib] = useState<string | null>(null)
  const [errorCommits, setErrorCommits] = useState<string | null>(null)
  // Contributors pagination/filters
  const [contribPage, setContribPage] = useState(1)
  const [contribPageSize, setContribPageSize] = useState(10)
  const [contribSearch, setContribSearch] = useState('')
  const [contribSort, setContribSort] = useState<'commits' | 'recent'>('commits')
  const [contribHasMore, setContribHasMore] = useState(false)
  // Commits pagination/filters
  const [commitPage, setCommitPage] = useState(1)
  const [commitPageSize, setCommitPageSize] = useState(20)
  const [commitSearch, setCommitSearch] = useState('')
  const [commitHasMore, setCommitHasMore] = useState(false)

  // Map language names to Tailwind color classes (kept explicit to avoid purge)
  function langColorClass(language: string): string {
    const m: Record<string, string> = {
      'JavaScript': 'bg-yellow-400',
      'TypeScript': 'bg-blue-400',
      'Python': 'bg-green-500',
      'Go': 'bg-cyan-500',
      'Rust': 'bg-orange-500',
      'Java': 'bg-red-400',
      'C': 'bg-slate-500',
      'C++': 'bg-indigo-500',
      'C#': 'bg-purple-500',
      'Ruby': 'bg-rose-400',
      'PHP': 'bg-violet-400',
      'Shell': 'bg-lime-500',
      'HCL': 'bg-emerald-400',
      'Kotlin': 'bg-fuchsia-500',
      'Swift': 'bg-orange-400',
      'HTML': 'bg-amber-400',
      'CSS': 'bg-pink-400',
      'SCSS': 'bg-pink-500',
      'Dockerfile': 'bg-teal-500',
      'Makefile': 'bg-slate-400',
    }
    return m[language] || 'bg-slate-300'
  }

  useEffect(() => {
    setLoading(true)
    xhrGetJson(`${base}/db/projects?select=id,uuid,name,repo_url,description,is_active,contributors_count,last_commit_at,primary_language,total_loc,created_at,updated_at&uuid=eq.${encodeURIComponent(uuid)}`)
      .then((rows) => {
        const p = (rows || [])[0] as ApiProject | undefined
        if (p) {
          setItem(p)
          setForm({ name: p.name, repo_url: p.repo_url || '', description: p.description || '', is_active: !!p.is_active })
        } else {
          setError('Project not found')
        }
      })
      .catch((err: any) => setError(err?.message || 'Failed to load project'))
      .finally(() => setLoading(false))
  }, [base, uuid])

  // Load languages breakdown
  useEffect(() => {
    if (!uuid) return
    setLoadingLangs(true)
    setErrorLangs(null)
    const url = `${base}/db/project_languages?select=language,bytes,loc,files,is_primary&project_id=eq.${encodeURIComponent(uuid)}&order=bytes.desc`
    xhrGetJson(url)
      .then((rows) => setLangs(rows || []))
      .catch((e: any) => setErrorLangs(e?.message || 'Failed to load languages'))
      .finally(() => setLoadingLangs(false))
  }, [base, uuid])

  // Load contributors and recent commits
  useEffect(() => {
    if (!uuid) return
    setLoadingContrib(true)
    setErrorContrib(null)
    const order = contribSort === 'commits' ? 'commits_count.desc' : 'last_commit_at.desc'
    const limit = contribPageSize
    const offset = (contribPage - 1) * contribPageSize
    let url = `${base}/db/project_contributors?select=login,display_name,email,commits_count,last_commit_at&project_id=eq.${encodeURIComponent(uuid)}&order=${encodeURIComponent(order)}&limit=${limit}&offset=${offset}`
    if (contribSearch.trim()) {
      const q = contribSearch.trim()
      url += `&login=ilike.*${encodeURIComponent(q)}*`
    }
    xhrGetJson(url)
      .then((rows) => {
        const arr = rows || []
        setContributors(arr)
        setContribHasMore(arr.length >= contribPageSize)
      })
      .catch((e: any) => setErrorContrib(e?.message || 'Failed to load contributors'))
      .finally(() => setLoadingContrib(false))
  }, [base, uuid, contribPage, contribPageSize, contribSearch, contribSort])

  useEffect(() => {
    if (!uuid) return
    setLoadingCommits(true)
    setErrorCommits(null)
    const limit = commitPageSize
    const offset = (commitPage - 1) * commitPageSize
    let url = `${base}/db/project_commits?select=sha,author_login,author_email,committed_at,message,url&project_id=eq.${encodeURIComponent(uuid)}&order=committed_at.desc&limit=${limit}&offset=${offset}`
    if (commitSearch.trim()) {
      const q = commitSearch.trim()
      url += `&message=ilike.*${encodeURIComponent(q)}*`
    }
    xhrGetJson(url)
      .then((rows) => {
        const arr = rows || []
        setCommits(arr)
        setCommitHasMore(arr.length >= commitPageSize)
      })
      .catch((e: any) => setErrorCommits(e?.message || 'Failed to load commits'))
      .finally(() => setLoadingCommits(false))
  }, [base, uuid, commitPage, commitPageSize, commitSearch])

  async function save() {
    if (!item || !form) return
    setSaving(true)
    setError(null)
    try {
      await xhrPostJson(`${base}/db/rpc/update_project`, {
        p_uuid: item.uuid,
        p_name: form.name,
        p_repo_url: form.repo_url || null,
        p_description: form.description || null,
        p_is_active: form.is_active,
      })
    } catch (e: any) {
      setError(e?.message || 'Failed to save')
    } finally {
      setSaving(false)
    }
  }

  const repo = ownerRepoFromUrl(item?.repo_url || null)
  const repoName = useMemo(() => (repo ? repo.split('/')[1] : null), [repo])
  const scanHref = useMemo(() => {
    if (!item) return '#'
    const u = new URL('http://localhost:5173/')
    u.searchParams.set('project_uuid', item.uuid)
    if (repo) u.searchParams.set('repo', repo)
    return u.toString()
  }, [item, repo])

  if (loading) return <div className="p-4">Loading…</div>
  if (error) return (
    <div className="p-4">
      <div className="text-red-700 bg-red-50 border border-red-200 rounded p-3 mb-3">{error}</div>
      <a href="/projects" className="text-blue-600 hover:underline">Back to Projects</a>
    </div>
  )
  if (!item || !form) return null

  return (
    <div className="min-h-screen bg-slate-50 text-slate-900">
      <header className="flex items-center justify-between p-4 border-b bg-white sticky top-0">
        <nav className="text-sm"><a href="/projects" className="text-blue-600 hover:underline">Projects</a> /</nav>
        <div className="flex items-center gap-2">
          <a href={scanHref} className="bg-amber-500 text-white px-3 py-1 rounded">Scan Repo</a>
          <button onClick={save} disabled={saving} className="bg-blue-600 text-white px-3 py-1 rounded disabled:opacity-50">{saving ? 'Saving…' : 'Save'}</button>
        </div>
      </header>
      <main className="p-4 space-y-4">
        <div className="bg-white p-4 rounded shadow-sm">
          <h2 className="font-medium mb-3">Project Overview</h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <label className="text-sm">
              <div className="mb-1">Name</div>
              <input className="border rounded px-2 py-1 w-full" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />
            </label>
            <label className="text-sm">
              <div className="mb-1">Repository URL</div>
              <input className="border rounded px-2 py-1 w-full" value={form.repo_url} onChange={(e) => setForm({ ...form, repo_url: e.target.value })} placeholder="https://github.com/owner/repo" />
            </label>
            <label className="text-sm md:col-span-2">
              <div className="mb-1">Description</div>
              <textarea className="border rounded px-2 py-1 w-full min-h-[80px]" value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} />
            </label>
            <label className="text-sm flex items-center gap-2">
              <input type="checkbox" checked={form.is_active} onChange={(e) => setForm({ ...form, is_active: e.target.checked })} />
              <span>Active</span>
            </label>
            <div className="text-sm md:col-span-1">
              <div className="mb-1">Primary language</div>
              {item?.primary_language ? (
                <span className="inline-block rounded border border-slate-200 bg-slate-100 px-2 py-0.5 text-xs">
                  {item.primary_language}
                </span>
              ) : (
                <span className="text-slate-400 text-xs">—</span>
              )}
            </div>
            <div className="text-sm md:col-span-1">
              <div className="mb-1">Total Lines of Code (LOC)</div>
              <div className="px-2 py-1 border rounded bg-slate-50 text-slate-700">
                {typeof item?.total_loc === 'number' ? item.total_loc.toLocaleString() : '—'}
              </div>
            </div>
            {(typeof item?.contributors_count !== 'undefined' || item?.last_commit_at) ? (
              <div className="text-sm text-slate-600 md:col-span-2">
                <span className="mr-4">Contributors: <strong>{item?.contributors_count ?? 0}</strong></span>
                {item?.last_commit_at ? <span>Last commit: <strong>{new Date(item.last_commit_at).toLocaleString()}</strong></span> : null}
              </div>
            ) : null}
          </div>
        </div>

        <OssVulnTables repoName={repoName} />

        <div className="bg-white p-4 rounded shadow-sm">
          <h2 className="font-medium mb-2">Languages Breakdown</h2>
          {loadingLangs ? (
            <div className="text-sm text-slate-600">Loading…</div>
          ) : errorLangs ? (
            <div className="text-sm text-red-700">{errorLangs}</div>
          ) : langs.length === 0 ? (
            <div className="text-sm text-slate-600">No language data yet.</div>
          ) : (
            <div className="space-y-3">
              {(() => {
                const total = langs.reduce((s, l) => s + (l.bytes || 0), 0)
                return (
                  <div className="w-full">
                    <div className="h-3 w-full flex overflow-hidden rounded border border-slate-200">
                      {langs.map((l) => {
                        const pct = total > 0 ? (l.bytes / total) * 100 : 0
                        const color = langColorClass(l.language)
                        return (
                          <div key={l.language} title={`${l.language} ${pct.toFixed(1)}%`} style={{ width: `${pct}%` }} className={`${color}`} />
                        )
                      })}
                    </div>
                    <div className="text-xs text-slate-500 mt-1">
                      Total: {(() => {
                        const totalB = langs.reduce((s, l) => s + (l.bytes || 0), 0)
                        const units = ['B', 'KB', 'MB', 'GB']
                        let v = totalB
                        let i = 0
                        while (v >= 1024 && i < units.length - 1) { v /= 1024; i++ }
                        return `${v.toFixed(v >= 10 ? 0 : 1)} ${units[i]}`
                      })()}
                    </div>
                  </div>
                )
              })()}
              <ul className="divide-y">
                {langs.map((l) => {
                  const total = langs.reduce((s, x) => s + (x.bytes || 0), 0)
                  const pct = total > 0 ? (l.bytes / total) * 100 : 0
                  return (
                    <li key={l.language} className="py-1.5 text-sm flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <span className={`inline-block w-3 h-3 rounded-full border border-white shadow-sm ${langColorClass(l.language)}`}></span>
                        <span className="font-medium">{l.language}</span>
                        {l.is_primary ? <span className="text-xs text-amber-700 bg-amber-100 border border-amber-200 px-1 rounded">Primary</span> : null}
                      </div>
                      <div className="text-right text-slate-600">
                        <span className="mr-3 font-mono">LOC: {l.loc?.toLocaleString?.() ?? l.loc}</span>
                        <span className="mr-3">{(() => {
                          const units = ['B', 'KB', 'MB', 'GB']
                          let v = l.bytes
                          let i = 0
                          while (v >= 1024 && i < units.length - 1) { v /= 1024; i++ }
                          return `${v.toFixed(v >= 10 ? 0 : 1)} ${units[i]}`
                        })()}</span>
                        <span className="mr-3">Files: {l.files?.toLocaleString?.() ?? l.files}</span>
                        <span>{pct.toFixed(1)}%</span>
                      </div>
                    </li>
                  )
                })}
              </ul>
            </div>
          )}
        </div>

        <div className="bg-white p-4 rounded shadow-sm">
          <h2 className="font-medium mb-2">Contributors</h2>
          <div className="flex flex-wrap items-center gap-2 mb-3 text-sm">
            <input className="border rounded px-2 py-1" placeholder="Filter by login…" value={contribSearch} onChange={(e) => { setContribPage(1); setContribSearch(e.target.value); }} />
            <select className="border rounded px-2 py-1" value={contribSort} onChange={(e) => { setContribPage(1); setContribSort((e.target.value as 'commits'|'recent')); }}>
              <option value="commits">Sort: Most commits</option>
              <option value="recent">Sort: Most recent</option>
            </select>
            <select className="border rounded px-2 py-1" value={contribPageSize} onChange={(e) => { setContribPage(1); setContribPageSize(parseInt(e.target.value || '10', 10)); }}>
              <option value={5}>5</option>
              <option value={10}>10</option>
              <option value={20}>20</option>
            </select>
            <div className="ml-auto flex items-center gap-2">
              <button className="border rounded px-2 py-1 disabled:opacity-50" onClick={() => setContribPage((p) => Math.max(1, p - 1))} disabled={contribPage <= 1}>Prev</button>
              <div>Page {contribPage}</div>
              <button className="border rounded px-2 py-1 disabled:opacity-50" onClick={() => setContribPage((p) => p + 1)} disabled={!contribHasMore}>Next</button>
            </div>
          </div>
          {loadingContrib ? (
            <div className="text-sm text-slate-600">Loading…</div>
          ) : errorContrib ? (
            <div className="text-sm text-red-700">{errorContrib}</div>
          ) : contributors.length === 0 ? (
            <div className="text-sm text-slate-600">No contributors found.</div>
          ) : (
            <ul className="divide-y">
              {contributors.map((c: { login: string; display_name?: string | null; email?: string | null; commits_count?: number; last_commit_at?: string | null }, idx: number) => (
                <li key={idx} className="py-2 text-sm flex items-center justify-between">
                  <div>
                    <div className="font-medium">{c.display_name || c.login}<span className="text-slate-500">{c.display_name ? ` (@${c.login})` : ''}</span></div>
                    <div className="text-slate-500">{c.email || ''} {c.last_commit_at ? `• Last: ${new Date(c.last_commit_at).toLocaleString()}` : ''}</div>
                  </div>
                  <div className="text-right"><span className="text-slate-500">Commits</span> <span className="font-semibold">{c.commits_count ?? 0}</span></div>
                </li>
              ))}
            </ul>
          )}
        </div>

        <div className="bg-white p-4 rounded shadow-sm">
          <h2 className="font-medium mb-2">Commit History</h2>
          <div className="flex flex-wrap items-center gap-2 mb-3 text-sm">
            <input className="border rounded px-2 py-1" placeholder="Filter by message…" value={commitSearch} onChange={(e) => { setCommitPage(1); setCommitSearch(e.target.value); }} />
            <select className="border rounded px-2 py-1" value={commitPageSize} onChange={(e) => { setCommitPage(1); setCommitPageSize(parseInt(e.target.value || '20', 10)); }}>
              <option value={10}>10</option>
              <option value={20}>20</option>
              <option value={50}>50</option>
            </select>
            <div className="ml-auto flex items-center gap-2">
              <button className="border rounded px-2 py-1 disabled:opacity-50" onClick={() => setCommitPage((p) => Math.max(1, p - 1))} disabled={commitPage <= 1}>Prev</button>
              <div>Page {commitPage}</div>
              <button className="border rounded px-2 py-1 disabled:opacity-50" onClick={() => setCommitPage((p) => p + 1)} disabled={!commitHasMore}>Next</button>
            </div>
          </div>
          {loadingCommits ? (
            <div className="text-sm text-slate-600">Loading…</div>
          ) : errorCommits ? (
            <div className="text-sm text-red-700">{errorCommits}</div>
          ) : commits.length === 0 ? (
            <div className="text-sm text-slate-600">No commits found.</div>
          ) : (
            <ul className="divide-y">
              {commits.map((c: { sha: string; author_login?: string | null; author_email?: string | null; committed_at: string; message?: string | null; url?: string | null }, idx: number) => (
                <li key={idx} className="py-2 text-sm">
                  <div className="flex items-center justify-between">
                    <div className="font-medium truncate max-w-[70%]">{c.message || '(no message)'}</div>
                    <div className="text-slate-500 ml-3 whitespace-nowrap">{new Date(c.committed_at).toLocaleString()}</div>
                  </div>
                  <div className="text-slate-500">{c.author_login ? `@${c.author_login}` : (c.author_email || '')} • <a className="text-blue-600 hover:underline" href={c.url || '#'} target="_blank" rel="noreferrer">{c.sha?.slice(0,7)}</a></div>
                </li>
              ))}
            </ul>
          )}
        </div>
      </main>
    </div>
  )
}
