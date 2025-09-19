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
        <h1 className="font-semibold">Security Portal</h1>
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
      </main>
    </div>
  )
}
