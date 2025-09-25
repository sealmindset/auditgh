import { useEffect, useMemo, useRef, useState } from 'react'
import { xhrGetJson, xhrPostJson, xhrPost } from './lib/xhr'

type Project = { id: string; api_id: number; name: string; repo_url: string | null; description: string | null }
type Scan = { id: string; project_id: string; status: string; started_at?: string | null; finished_at?: string | null }

function AuthBadge() {
  const [status, setStatus] = useState<{authDisabled:boolean, authenticated:boolean} | null>(null)
  useEffect(() => {
    const base = window.location.origin
    xhrGetJson(`${base}/auth/me`).then(setStatus).catch(() => {})
  }, [])
  if (!status?.authDisabled) return null
  return <div className="bg-yellow-100 text-yellow-800 text-xs px-2 py-1 rounded">AUTH DISABLED (DEV ONLY)</div>
}

export default function App() {
  const [projects, setProjects] = useState<Project[]>([])
  const [loadingProjects, setLoadingProjects] = useState(false)
  const [selectedProject, setSelectedProject] = useState<string>('')

  const [scan, setScan] = useState<Scan | null>(null)
  const [logs, setLogs] = useState<string[]>([])
  const [streaming, setStreaming] = useState(false)
  const esRef = useRef<EventSource | null>(null)
  const logsEndRef = useRef<HTMLDivElement | null>(null)
  const base = useMemo(() => window.location.origin, [])
  const [starting, setStarting] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [connected, setConnected] = useState(false)
  const [copied, setCopied] = useState(false)
  const allScanners = useMemo(() => ['cicd','gitleaks','hardcoded_ips','oss','terraform','codeql','contributors','binaries','linecount'] as const, [])
  const [selectedScanners, setSelectedScanners] = useState<string[]>([...allScanners])
  const [profile, setProfile] = useState<'fast'|'balanced'|'deep'>('balanced')
  const urlParams = useMemo(() => new URLSearchParams(window.location.search), [])
  const repoParam = urlParams.get('repo') || ''
  const [scope, setScope] = useState<'org'|'repo'>(repoParam ? 'repo' : 'org')
  // CodeQL options
  const codeqlSupportedLangs = useMemo(() => ['cpp','csharp','go','java','javascript','python','ruby','swift','kotlin'] as const, [])
  const [codeqlLangs, setCodeqlLangs] = useState<string[]>([])
  const [codeqlSkipAutobuild, setCodeqlSkipAutobuild] = useState(false)
  const [codeqlRecreateDb, setCodeqlRecreateDb] = useState(false)

  // CodeQL findings table state
  const [cqRepo, setCqRepo] = useState<string>(repoParam ? (repoParam.includes('/') ? repoParam.split('/').pop() as string : repoParam) : '')
  const [cqFindings, setCqFindings] = useState<any[]>([])
  const [cqTotal, setCqTotal] = useState(0)
  const [cqPage, setCqPage] = useState(0)
  const [cqPageSize, setCqPageSize] = useState(25)
  const [cqSearch, setCqSearch] = useState('')
  const defaultSeverities = useMemo(() => ["critical","high","medium","low","info","unknown"] as const, [])
  const [cqSev, setCqSev] = useState<string[]>([...defaultSeverities])
  const [cqSort, setCqSort] = useState<'severity'|'rule'|'file'|'line'>('severity')
  const [cqDir, setCqDir] = useState<'asc'|'desc'>('desc')
  const [cqLoading, setCqLoading] = useState(false)
  const [cqError, setCqError] = useState<string|null>(null)
  const [repoOptions, setRepoOptions] = useState<string[]>([])
  const [loadingRepos, setLoadingRepos] = useState(false)
  const [cqTotals, setCqTotals] = useState<{ total: number; critical: number; high: number; medium: number; low: number; info: number; unknown: number }>({ total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0, unknown: 0 })

  useEffect(() => {
    setLoadingProjects(true)
    xhrGetJson(`${base}/api/projects`).then(d => {
      setProjects(d.data || [])
      const qp = urlParams.get('project_uuid')
      if (qp && (d?.data || []).some((p: any) => p.id === qp)) {
        setSelectedProject(qp)
      } else if (!selectedProject && d?.data?.length) {
        setSelectedProject(d.data[0].id)
      }
    }).catch(err => {
      console.error('Failed to load projects', err)
      setLogs(prev => [...prev, 'Failed to load projects'])
    }).finally(() => setLoadingProjects(false))
  }, [base, urlParams])

  useEffect(() => {
    logsEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [logs])

  const selected = useMemo(() => projects.find(p => p.id === selectedProject) || null, [projects, selectedProject])

  function stopStream() {
    esRef.current?.close();
    esRef.current = null;
    setStreaming(false)
    setConnected(false)
  }

  async function startScan() {
    if (!selected) return
    stopStream()
    setLogs([])
    setError(null)
    setStarting(true)
    try {
      const payload: any = { project_id: selected.id, profile, scanners: selectedScanners }
      if (scope === 'repo' && repoParam) { payload.scope = 'repo'; payload.repo = repoParam }
      else { payload.scope = 'org' }
      // Pass CodeQL-specific options when CodeQL scanner is selected
      if (selectedScanners.includes('codeql')) {
        if (codeqlLangs.length > 0) payload.codeql_languages = codeqlLangs
        if (codeqlSkipAutobuild) payload.codeql_skip_autobuild = true
        if (codeqlRecreateDb) payload.codeql_recreate_db = true
      }
      const data = await xhrPostJson(`${base}/api/scans/`, payload)
      const s: Scan = data.data
      setScan(s)
      const es = new EventSource(`${base}/api/scans/${s.id}/stream`)
      esRef.current = es
      setStreaming(true)
      setConnected(false)
      es.onopen = () => setConnected(true)
      es.onmessage = (ev) => {
        try {
          const e = JSON.parse(ev.data)
          if (e?.message) setLogs(prev => [...prev, e.message as string])
          if (e?.type === 'done') {
            setStreaming(false)
            setConnected(false)
            // Auto-load repos and findings/totals for this scan when it finishes
            // eslint-disable-next-line @typescript-eslint/no-floating-promises
            loadRepoOptions()
            // If a repo is already set, refresh findings/totals
            if (cqRepo) {
              // eslint-disable-next-line @typescript-eslint/no-floating-promises
              loadFindings(0)
              // eslint-disable-next-line @typescript-eslint/no-floating-promises
              loadCqTotals()
            }
          }
        } catch {
          // ignore parse errors
        }
      }
      es.onerror = () => {
        setError('SSE stream error')
        setLogs(prev => [...prev, 'SSE stream error'])
        stopStream()
      }
    } catch (err: any) {
      const msg = `Failed to start scan: ${err?.message || String(err)}`
      setError(msg)
      setLogs(prev => [...prev, msg])
    } finally {
      setStarting(false)
    }
  }

  async function cancelScan() {
    if (!scan) return
    await xhrPost(`${base}/api/scans/${scan.id}/cancel`)
    stopStream()
  }

  async function loadFindings(page = cqPage) {
    if (!scan) return
    if (!cqRepo) { setCqError('Repo name is required'); return }
    setCqError(null)
    setCqLoading(true)
    try {
      const params = new URLSearchParams()
      params.set('repo', cqRepo)
      if (cqSearch) params.set('search', cqSearch)
      if (cqSev.length) params.set('severity', cqSev.join(','))
      params.set('limit', String(cqPageSize))
      params.set('offset', String(page * cqPageSize))
      params.set('sort', cqSort)
      params.set('dir', cqDir)
      const url = `${base}/api/scans/${scan.id}/codeql/findings?${params.toString()}`
      const data = await xhrGetJson(url)
      setCqFindings(data?.data?.items || [])
      setCqTotal(Number(data?.data?.total || 0))
      setCqPage(page)
    } catch (e: any) {
      setCqError(e?.message || 'Failed to load findings')
    } finally {
      setCqLoading(false)
    }
  }

  // Load detected repos for this scan and auto-select first if none set
  async function loadRepoOptions() {
    if (!scan) return
    setLoadingRepos(true)
    try {
      const url = `${base}/api/scans/${scan.id}/codeql/repos`
      const data = await xhrGetJson(url)
      const opts = (data?.data || []) as string[]
      setRepoOptions(opts)
      if (!cqRepo && opts.length > 0) {
        setCqRepo(opts[0])
        // eslint-disable-next-line @typescript-eslint/no-floating-promises
        loadFindings(0)
        // eslint-disable-next-line @typescript-eslint/no-floating-promises
        loadCqTotals(opts[0])
      }
    } catch {
      // ignore
    } finally {
      setLoadingRepos(false)
    }
  }

  // Load severity totals for the selected repo
  async function loadCqTotals(selectedRepo?: string) {
    if (!scan) return
    const repoSel = (selectedRepo || cqRepo || '').trim()
    if (!repoSel) return
    try {
      const url = `${base}/api/scans/${scan.id}/codeql/severity-totals?repo=${encodeURIComponent(repoSel)}`
      const data = await xhrGetJson(url)
      const d = (data?.data || {}) as any
      setCqTotals({
        total: Number(d.total || 0),
        critical: Number(d.critical || 0),
        high: Number(d.high || 0),
        medium: Number(d.medium || 0),
        low: Number(d.low || 0),
        info: Number(d.info || 0),
        unknown: Number(d.unknown || 0),
      })
    } catch {
      setCqTotals({ total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0, unknown: 0 })
    }
  }

  // Auto-load repos when a scan is available
  useEffect(() => {
    if (!scan?.id) return
    // eslint-disable-next-line @typescript-eslint/no-floating-promises
    loadRepoOptions()
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [scan?.id])

  // Auto-refresh findings and totals when repo or filters change
  useEffect(() => {
    if (!scan?.id || !cqRepo) return
    // eslint-disable-next-line @typescript-eslint/no-floating-promises
    loadFindings(0)
    // eslint-disable-next-line @typescript-eslint/no-floating-promises
    loadCqTotals()
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [scan?.id, cqRepo, cqSev, cqSort, cqDir, cqPageSize])

  async function copyLogs() {
    const text = logs.join('\n')
    try {
      if (navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(text)
      } else {
        const ta = document.createElement('textarea')
        ta.value = text
        document.body.appendChild(ta)
        ta.select()
        document.execCommand('copy')
        document.body.removeChild(ta)
      }
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    } catch {
      // ignore copy errors
    }
  }

  return (
    <div className="min-h-screen bg-slate-50 text-slate-900">
      <header className="flex items-center justify-between p-4 border-b bg-white sticky top-0">
        <h1 className="font-semibold">GitHub Auditor</h1>
        <AuthBadge />
      </header>
      <main className="p-4 space-y-4">
        {error && (
          <div role="alert" className="border rounded p-3 flex items-start justify-between bg-red-50 border-red-200 text-red-700">
            <div className="pr-3">{error}</div>
            <button onClick={() => setError(null)} aria-label="Dismiss error" className="px-2 py-1 hover:text-red-900">✕</button>
          </div>
        )}
        <div className="bg-white p-4 rounded shadow-sm">
          <h2 className="font-medium mb-2">Run Shai-Hulud Scan</h2>
          <div className="flex flex-col gap-3">
            <label className="text-sm">
              <span className="mr-2">Project</span>
              {loadingProjects ? (
                <span className="text-slate-500">Loading…</span>
              ) : (
                <select className="border rounded px-2 py-1" value={selectedProject} onChange={e => setSelectedProject(e.target.value)}>
                  {projects.map(p => (
                    <option key={p.id} value={p.id}>{p.name}</option>
                  ))}
                </select>
              )}
            </label>
            <div className="text-sm">
              <div className="mb-2 font-medium">Scope</div>
              <div className="flex items-center gap-4">
                <label className="flex items-center gap-1">
                  <input type="radio" name="scope" checked={scope==='org'} onChange={() => setScope('org')} />
                  <span>All repos in org</span>
                </label>
                <label className="flex items-center gap-1">
                  <input type="radio" name="scope" checked={scope==='repo'} onChange={() => setScope('repo')} />
                  <span>Single repo{repoParam ? `: ${repoParam}` : ''}</span>
                </label>
              </div>
            </div>
            <div className="text-sm">
              <div className="mb-2 font-medium">Profile</div>
              <div className="flex items-center gap-4">
                {(['fast','balanced','deep'] as const).map(pf => (
                  <label key={pf} className="flex items-center gap-1">
                    <input type="radio" name="profile" checked={profile===pf} onChange={() => setProfile(pf)} />
                    <span className="capitalize">{pf}</span>
                  </label>
                ))}
              </div>
            </div>
            <div className="text-sm">
              <div className="mb-2 flex items-center justify-between">
                <span className="font-medium">Scanners</span>
                <div className="flex gap-2 text-xs">
                  <button type="button" className="px-2 py-0.5 bg-slate-200 rounded" onClick={() => setSelectedScanners([...allScanners])}>Select all</button>
                  <button type="button" className="px-2 py-0.5 bg-slate-200 rounded" onClick={() => setSelectedScanners([])}>Deselect all</button>
                </div>
              </div>
              <div className="grid grid-cols-2 md:grid-cols-3 gap-2">
                {allScanners.map(s => (
                  <label key={s} className="flex items-center gap-2 border rounded px-2 py-1">
                    <input
                      type="checkbox"
                      checked={selectedScanners.includes(s)}
                      onChange={(e) => {
                        setSelectedScanners(prev => e.target.checked ? Array.from(new Set([...prev, s])) : prev.filter(x => x !== s))
                      }}
                    />
                    <span className="capitalize">{s.replace('_',' ')}</span>
                  </label>
                ))}
              </div>
              {selectedScanners.includes('codeql') && (
                <div className="mt-3 border rounded p-3 bg-slate-50">
                  <div className="mb-2 font-medium">CodeQL Options</div>
                  <div className="text-xs text-slate-600 mb-2">Languages (optional; leave empty to auto-detect)</div>
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
                    {codeqlSupportedLangs.map(l => (
                      <label key={l as string} className="flex items-center gap-2 border rounded px-2 py-1">
                        <input
                          type="checkbox"
                          checked={codeqlLangs.includes(l as string)}
                          onChange={(e) => {
                            setCodeqlLangs(prev => e.target.checked
                              ? Array.from(new Set([...prev, l as string]))
                              : prev.filter(x => x !== (l as string)))
                          }}
                        />
                        <span className="uppercase text-xs">{l as string}</span>
                      </label>
                    ))}
                  </div>
                  <div className="mt-2 flex gap-2 text-xs">
                    <button type="button" className="px-2 py-0.5 bg-slate-200 rounded" onClick={() => setCodeqlLangs([])}>Auto-detect</button>
                    <button type="button" className="px-2 py-0.5 bg-slate-200 rounded" onClick={() => setCodeqlLangs(['python'])}>Python only</button>
                    <button type="button" className="px-2 py-0.5 bg-slate-200 rounded" onClick={() => setCodeqlLangs(Array.from(codeqlSupportedLangs as unknown as string[]))}>All</button>
                    <button
                      type="button"
                      className="px-2 py-0.5 bg-amber-200 rounded"
                      title="Set languages to Python and enable Skip autobuild"
                      onClick={() => { setCodeqlLangs(['python']); setCodeqlSkipAutobuild(true); }}
                    >
                      Python-only + Skip autobuild
                    </button>
                  </div>
                  <label className="mt-3 flex items-center gap-2 text-sm">
                    <input type="checkbox" checked={codeqlSkipAutobuild} onChange={(e) => setCodeqlSkipAutobuild(e.target.checked)} />
                    <span>Skip autobuild for compiled languages</span>
                  </label>
                  <label className="mt-2 flex items-center gap-2 text-sm">
                    <input type="checkbox" checked={codeqlRecreateDb} onChange={(e) => setCodeqlRecreateDb(e.target.checked)} />
                    <span>Recreate CodeQL DB (avoid cached DB issues)</span>
                  </label>
                </div>
              )}
            </div>
            <div className="flex gap-2">
              <button onClick={startScan} aria-busy={starting} disabled={!selected || starting} className="bg-blue-600 text-white px-3 py-1 rounded disabled:opacity-50 flex items-center gap-2">
                {starting && (
                  <svg className="animate-spin h-4 w-4 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" aria-hidden="true">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v4a4 4 0 00-4 4H4z"></path>
                  </svg>
                )}
                {starting ? 'Starting…' : 'Start Scan'}
              </button>
              <button onClick={cancelScan} disabled={!scan || !streaming || starting} className="bg-slate-200 px-3 py-1 rounded disabled:opacity-50">Cancel</button>
            </div>
          </div>
        </div>

        <div className="bg-white p-4 rounded shadow-sm">
          <div className="flex items-center justify-between mb-2">
            <div className="flex items-center gap-2">
              <h2 className="font-medium">Live Output</h2>
              <span className="flex items-center gap-1 text-xs">
                <span className={connected ? 'h-2 w-2 rounded-full bg-green-500' : 'h-2 w-2 rounded-full bg-slate-400'}></span>
                {connected ? 'connected' : 'disconnected'}
              </span>
            </div>
            <button onClick={copyLogs} disabled={!logs.length} className="text-xs bg-slate-200 px-2 py-1 rounded disabled:opacity-50 hover:bg-slate-300">
              {copied ? 'Copied' : 'Copy logs'}
            </button>
          </div>
          <div className="h-64 overflow-auto border rounded bg-black text-green-300 p-2 font-mono text-xs">
            {logs.map((l, i) => (
              <div key={i}>{l}</div>
            ))}
            <div ref={logsEndRef} />
          </div>
        </div>

        {/* CodeQL Findings Panel */}
        <div className="bg-white p-4 rounded shadow-sm">
          <div className="flex items-center justify-between mb-2">
            <h2 className="font-medium">CodeQL Findings</h2>
            <div className="text-xs text-slate-600">{scan ? `Scan: ${scan.id}` : 'Start a scan to enable findings'}</div>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-4 gap-3 mb-3 text-sm">
            <label className="flex flex-col">
              <span className="text-xs text-slate-600">Repo (short name)</span>
              <input className="border rounded px-2 py-1" value={cqRepo} onChange={e => setCqRepo(e.target.value)} placeholder="e.g. oscp" />
            </label>
            <label className="flex flex-col">
              <span className="text-xs text-slate-600">Search</span>
              <input className="border rounded px-2 py-1" value={cqSearch} onChange={e => setCqSearch(e.target.value)} placeholder="rule/file/message" />
            </label>
            <label className="flex flex-col">
              <span className="text-xs text-slate-600">Page size</span>
              <select className="border rounded px-2 py-1" value={cqPageSize} onChange={e => setCqPageSize(parseInt(e.target.value))}>
                {[10,25,50,100].map(n => <option key={n} value={n}>{n}</option>)}
              </select>
            </label>
            <div className="flex items-end gap-2">
              <button className="px-3 py-1 bg-slate-200 rounded" disabled={!scan || cqLoading} onClick={() => loadFindings(0)}>Refresh</button>
              <button className="px-3 py-1 bg-slate-100 rounded" onClick={() => { setCqSearch(''); setCqSev([...defaultSeverities]); setCqSort('severity'); setCqDir('desc'); setCqPage(0); setCqFindings([]); setCqTotal(0); }}>Reset</button>
            </div>
          </div>
          {/* Totals bar with click-to-filter */}
          <div className="text-xs mb-2 flex flex-wrap items-center gap-2">
            <span className="mr-1">Totals:</span>
            <button className={`px-2 py-0.5 rounded border ${cqSev.length===defaultSeverities.length ? 'bg-slate-800 text-white' : 'bg-slate-100'}`} onClick={() => { setCqSev([...defaultSeverities]); setCqPage(0) }}>All {cqTotals.total}</button>
            <button className="px-2 py-0.5 rounded text-white bg-red-600" onClick={() => { setCqSev(['critical']); setCqPage(0) }}>Critical {cqTotals.critical}</button>
            <button className="px-2 py-0.5 rounded text-white bg-red-500" onClick={() => { setCqSev(['high']); setCqPage(0) }}>High {cqTotals.high}</button>
            <button className="px-2 py-0.5 rounded bg-amber-400" onClick={() => { setCqSev(['medium']); setCqPage(0) }}>Medium {cqTotals.medium}</button>
            <button className="px-2 py-0.5 rounded bg-yellow-200" onClick={() => { setCqSev(['low']); setCqPage(0) }}>Low {cqTotals.low}</button>
            <button className="px-2 py-0.5 rounded bg-blue-200" onClick={() => { setCqSev(['info']); setCqPage(0) }}>Info {cqTotals.info}</button>
            <button className="px-2 py-0.5 rounded bg-slate-200" onClick={() => { setCqSev(['unknown']); setCqPage(0) }}>Unknown {cqTotals.unknown}</button>
          </div>
          <div className="text-xs mb-2">
            <span className="mr-2">Severity:</span>
            {["critical","high","medium","low","info","unknown"].map(s => (
              <label key={s} className="mr-3 inline-flex items-center gap-1">
                <input type="checkbox" checked={cqSev.includes(s)} onChange={(e) => setCqSev(prev => e.target.checked ? Array.from(new Set([...prev, s])) : prev.filter(x => x!==s))} />
                <span className="capitalize">{s}</span>
              </label>
            ))}
          </div>
          {cqError && <div className="text-red-600 text-sm mb-2">{cqError}</div>}
          <div className="overflow-auto border rounded">
            <table className="min-w-full text-sm">
              <thead className="bg-slate-100">
                <tr>
                  {([['Severity','severity'],['Rule','rule'],['File','file'],['Line','line'],['Message','message'],['Docs','docs']] as const).map(([label,key]) => (
                    <th key={key} className="text-left px-2 py-1 cursor-pointer select-none" onClick={() => { if (key==='docs' || key==='message') return; const k = key as 'severity'|'rule'|'file'|'line'; if (cqSort===k) setCqDir(cqDir==='asc'?'desc':'asc'); else { setCqSort(k); setCqDir('asc'); } }}>
                      {label}{(cqSort===key ? (cqDir==='asc'?' ▲':' ▼') : '')}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {cqLoading ? (
                  <tr><td colSpan={6} className="px-2 py-2 text-slate-500">Loading…</td></tr>
                ) : cqFindings.length === 0 ? (
                  <tr><td colSpan={6} className="px-2 py-2 text-slate-500">No findings</td></tr>
                ) : (
                  cqFindings.map((it, idx) => (
                    <tr key={idx} className="border-t">
                      <td className="px-2 py-1"><span className={`text-xs px-2 py-0.5 rounded ${
                        (it.severity||'').toLowerCase()==='critical' ? 'bg-red-600 text-white' :
                        (it.severity||'').toLowerCase()==='high' ? 'bg-red-500 text-white' :
                        (it.severity||'').toLowerCase()==='medium' ? 'bg-amber-400 text-black' :
                        (it.severity||'').toLowerCase()==='low' ? 'bg-yellow-200 text-black' :
                        (it.severity||'').toLowerCase()==='info' ? 'bg-blue-200 text-black' : 'bg-slate-200 text-black'}`}>{(it.severity||'unknown').toUpperCase()}</span></td>
                      <td className="px-2 py-1 whitespace-nowrap">{it.rule_id || ''}</td>
                      <td className="px-2 py-1 whitespace-nowrap">{it.file || ''}</td>
                      <td className="px-2 py-1">{it.line || ''}</td>
                      <td className="px-2 py-1 max-w-[40rem] truncate" title={it.message || ''}>{it.message || ''}</td>
                      <td className="px-2 py-1">{it.help_uri ? <a className="text-blue-600 underline" href={it.help_uri} target="_blank" rel="noreferrer">Docs</a> : <span className="text-slate-400">—</span>}</td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
          <div className="flex items-center justify-between mt-2 text-xs">
            <div>
              {cqTotal > 0 ? (
                <span>Showing {cqPage*cqPageSize + (cqFindings.length?1:0)}–{cqPage*cqPageSize + cqFindings.length} of {cqTotal}</span>
              ) : (
                <span>Showing 0 of 0</span>
              )}
            </div>
            <div className="flex gap-2">
              <button className="px-2 py-0.5 bg-slate-200 rounded disabled:opacity-50" disabled={cqPage===0 || cqLoading} onClick={() => loadFindings(Math.max(0, cqPage-1))}>Prev</button>
              <button className="px-2 py-0.5 bg-slate-200 rounded disabled:opacity-50" disabled={(cqPage+1)*cqPageSize>=cqTotal || cqLoading} onClick={() => loadFindings(cqPage+1)}>Next</button>
            </div>
          </div>
        </div>
      </main>
    </div>
  )
}
