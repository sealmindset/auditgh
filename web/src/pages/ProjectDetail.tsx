import { useEffect, useMemo, useState } from 'react'
import { xhrGetJson, xhrPostJson, xhrGetText } from '../lib/xhr'
import OssVulnTables from '../components/OssVulnTables'
import TerraformFindings from '../components/TerraformFindings'
import BinariesTable from '../components/BinariesTable'
import DataTable, { ColumnDef } from '../components/DataTable'
import AiAssistantPanel from '../components/AiAssistantPanel'
import { askAI, type AskAIContext } from '../lib/ask-ai'
import ExploitTypeGrid from '../components/ExploitTypeGrid'
import ExploitHelpModal from '../components/ExploitHelpModal'
import ChartHost from '../components/ChartKit/ChartHost'
import { ProjectKPIAdapter } from '../components/ChartKit/adapters/ProjectKPIAdapter'
import { ProjectLanguagesAdapter } from '../components/ChartKit/adapters/ProjectLanguagesAdapter'
import { ProjectContributorsAdapter } from '../components/ChartKit/adapters/ProjectContributorsAdapter'
import { ProjectCommitsActivityAdapter } from '../components/ChartKit/adapters/ProjectCommitsActivityAdapter'

export type ApiProject = { id: number; uuid: string; name: string; repo_url: string | null; description: string | null; is_active: boolean; created_at: string; updated_at?: string; contributors_count?: number; last_commit_at?: string | null; primary_language?: string | null; total_loc?: number; stars?: number | null; forks?: number | null }

function ownerRepoFromUrl(url: string | null): string | null {
  if (!url) return null
  const raw = url.trim()
  // Handle SSH format: git@github.com:owner/repo(.git)
  const sshMatch = /^git@[^:]+:([^\s]+)$/i.exec(raw)
  if (sshMatch) {
    const path = sshMatch[1].replace(/\.git$/i, '')
    const parts = path.split('/')
    if (parts.length >= 2) return `${parts[0]}/${parts[1]}`
    return null
  }
  // Handle plain owner/repo(.git)
  const plainMatch = /^([^\s/]+)\/([^\s/]+)(?:\.git)?$/i.exec(raw)
  if (plainMatch && !raw.includes('://')) {
    return `${plainMatch[1]}/${plainMatch[2].replace(/\.git$/i, '')}`
  }
  // Handle http(s) and git:// URLs
  try {
    const u = new URL(raw)
    const cleaned = u.pathname.replace(/^\//,'').replace(/\.git$/i, '')
    const parts = cleaned.split('/')
    if (parts.length >= 2) return `${parts[0]}/${parts[1]}`
    return null
  } catch {
    return null
  }
}

function normalizeRepoKey(s: string): string {
  return (s || '').toLowerCase().replace(/[^a-z0-9]+/g, '')
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
  // Contributors now paginated client-side via DataTable
  const [contribPage, setContribPage] = useState(1)
  const [contribPageSize, setContribPageSize] = useState(10)
  const [contribSearch, setContribSearch] = useState('')
  const [contribSort, setContribSort] = useState<'commits' | 'recent'>('commits')
  const [contribHasMore, setContribHasMore] = useState(false)
  // Commits pagination/filters
  // Commits now paginated client-side via DataTable
  const [commitPage, setCommitPage] = useState(1)
  const [commitPageSize, setCommitPageSize] = useState(10)
  const [commitSearch, setCommitSearch] = useState('')
  const [commitHasMore, setCommitHasMore] = useState(false)
  // CodeQL findings table state
  const [cqRepo, setCqRepo] = useState<string>('')
  const [cqFindings, setCqFindings] = useState<any[]>([])
  const [cqTotal, setCqTotal] = useState(0)
  // Findings now paginated client-side via DataTable
  const [cqPage, setCqPage] = useState(0)
  const [cqPageSize, setCqPageSize] = useState(10)
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
  const [cqAiCtx, setCqAiCtx] = useState<any | null>(null)
  const [cqExploitMap, setCqExploitMap] = useState<Record<string, { status: boolean | null; evidence: any[] }>>({})
  const [cqManageKey, setCqManageKey] = useState<string | null>(null)
  const [cqManageStatus, setCqManageStatus] = useState<boolean>(false)
  const [cqManageCitations, setCqManageCitations] = useState<string>('')

  // Fetch exploit statuses for CodeQL rule IDs when findings change
  useEffect(() => {
    async function fetchCqExploit() {
      try {
        const ids = Array.from(new Set((cqFindings||[]).map((r: any) => String(r.rule_id||'').trim()).filter(Boolean)))
        if (!ids.length) { setCqExploitMap({}); return }
        const url = `${base}/api/exploitability?type=codeql_rule&keys=${encodeURIComponent(ids.join(','))}`
        const data = await xhrGetJson(url)
        const out: Record<string, { status: boolean | null; evidence: any[] }> = {}
        for (const it of (data?.items||[])) out[String(it.key)] = { status: it.exploit_available===true ? true : (it.exploit_available===false ? false : null), evidence: it.evidence||[] }
        setCqExploitMap(out)
      } catch {
        // ignore
      }
    }
    // eslint-disable-next-line @typescript-eslint/no-floating-promises
    fetchCqExploit()
  }, [base, cqFindings])

  function openCqManage(ruleId: string) {
    const key = String(ruleId||'')
    setCqManageKey(key)
    const st = cqExploitMap[key]?.status ?? null
    setCqManageStatus(st === true)
    const ev = cqExploitMap[key]?.evidence || []
    setCqManageCitations((ev||[]).map((e:any)=>String(e.url||'')).filter(Boolean).join('\n'))
  }

  async function saveCqManage() {
    if (!cqManageKey) return
    const urls = cqManageCitations.split(/\s+/).map((s: string)=>s.trim()).filter(Boolean)
    if (cqManageStatus && urls.length===0) return
    try {
      const evidence = urls.map((u: string) => ({ url: u }))
      await xhrPostJson(`${base}/api/exploitability`, { type: 'codeql_rule', key: cqManageKey, exploit_available: !!cqManageStatus, evidence })
      const data = await xhrGetJson(`${base}/api/exploitability?type=codeql_rule&key=${encodeURIComponent(cqManageKey)}`)
      const it = (data?.items||[])[0]
      if (it) setCqExploitMap((prev) => ({ ...prev, [String(it.key)]: { status: it.exploit_available===true ? true : (it.exploit_available===false ? false : null), evidence: it.evidence||[] } }))
      setCqManageKey(null)
    } catch {
      // ignore
    }
  }

  // Combined Secrets (GenAI + Generic)
  const [aiTokens, setAiTokens] = useState<any[]>([])
  const [secretLeaks, setSecretLeaks] = useState<any[]>([])
  const [secretsLoading, setSecretsLoading] = useState(false)
  const [secretsError, setSecretsError] = useState<string|null>(null)
  const [isAdmin, setIsAdmin] = useState<boolean>(false)
  const [authChecked, setAuthChecked] = useState<boolean>(false)
  const [showValues, setShowValues] = useState<boolean>(false)
  // CI/CD (GitHub Actions) recent runs
  const [ciRuns, setCiRuns] = useState<any[]>([])
  const [ciLoading, setCiLoading] = useState(false)
  const [ciError, setCiError] = useState<string|null>(null)
  const [secretAiCtx, setSecretAiCtx] = useState<any | null>(null)
  const [ciAiCtx, setCiAiCtx] = useState<any | null>(null)
  const [contribAiCtx, setContribAiCtx] = useState<any | null>(null)
  const [commitAiCtx, setCommitAiCtx] = useState<any | null>(null)
  // Project Overview Exploit pill (aggregated across repo findings)
  const [overviewExploit, setOverviewExploit] = useState<boolean | null>(null)
  const [overviewExploitLoading, setOverviewExploitLoading] = useState<boolean>(false)
  const [exploitHelpOpen, setExploitHelpOpen] = useState<boolean>(false)

  // Ask AI drawer and table fullscreen overlay state
  const [askAiOpen, setAskAiOpen] = useState(false)
  const [askAiQuestion, setAskAiQuestion] = useState('')
  const [askAiResponse, setAskAiResponse] = useState<string>('')
  const [askAiBusy, setAskAiBusy] = useState(false)
  const [selection, setSelection] = useState<{ tableId: string; rowIndexes: number[] } | null>(null)

  const [fsOpen, setFsOpen] = useState(false)
  const [fsDensity, setFsDensity] = useState<'comfortable' | 'compact'>('comfortable')
  const [fsConfig, setFsConfig] = useState<{ id: string; name: string; fields?: Array<{key:string;label:string}>; columns?: ColumnDef<any>[]; rows: any[] } | null>(null)
  const [fsAiCtx, setFsAiCtx] = useState<any | null>(null)
  const [fsExploitType, setFsExploitType] = useState<'codeql_rule'|'terraform_rule'|'cve'|'ghsa'|null>(null)
  const [fsExploitMap, setFsExploitMap] = useState<Record<string, { status: boolean | null; evidence: any[] }>>({})
  const [fsManageKey, setFsManageKey] = useState<string | null>(null)
  const [fsManageStatus, setFsManageStatus] = useState<boolean>(false)
  const [fsManageCitations, setFsManageCitations] = useState<string>('')
  const fsEffectiveFields = useMemo(() => {
    if (!fsConfig) return [] as Array<{key:string;label:string}>
    if (fsConfig.columns && fsConfig.columns.length > 0) {
      return fsConfig.columns.map(c => ({ key: String(c.key), label: c.header }))
    }
    return fsConfig.fields || []
  }, [fsConfig])

  const overlayColumns = useMemo<ColumnDef<any>[]>(() => {
    if (!fsConfig) return []
    if (fsConfig.columns && fsConfig.columns.length > 0) {
      return fsConfig.columns.map((c) => {
        if (String(c.key) === 'ask_ai') {
          return {
            ...c,
            render: (row: any) => (
              <button
                type="button"
                className="text-xs px-2 py-0.5 border rounded"
                onClick={() => setFsAiCtx(row)}
              >
                Ask AI
              </button>
            ),
          } as ColumnDef<any>
        }
        if (String(c.key) === 'exploit') {
          return {
            ...c,
            render: (row: any) => {
              const key = fsConfig.id === 'oss' ? String((row.vuln_id || '')).toUpperCase() : String(row.rule_id || '')
              // Determine status label from overlay map or existing maps (for codeql)
              let st: boolean | null = null
              if (fsExploitMap && Object.prototype.hasOwnProperty.call(fsExploitMap, key)) {
                st = fsExploitMap[key]?.status ?? null
              } else if (fsConfig.id === 'codeql') {
                const m = (cqExploitMap || {})[key]
                st = m ? (m.status === true ? true : (m.status === false ? false : null)) : null
              }
              const cls = st===true ? 'bg-green-600 text-white' : st===false ? 'bg-slate-300 text-slate-900' : 'bg-slate-100 text-slate-800'
              const label = st===true ? 'True' : st===false ? 'False' : 'Unknown'
              return (
                <button
                  type="button"
                  className={`text-xs px-2 py-0.5 rounded border ${cls}`}
                  title="Manage exploit status"
                  onClick={() => openFsManage(key)}
                >
                  {label}
                </button>
              )
            }
          } as ColumnDef<any>
        }
        return c
      })
    }
    // Fallback: generate simple text columns from fields
    return fsEffectiveFields.map(f => ({ key: f.key, header: f.label, sortable: true, filter: { type: 'text' } }))
  }, [fsConfig, fsEffectiveFields, fsExploitMap])

  // Phase 2: Top controls – search and show-empty styling
  const [topQuery, setTopQuery] = useState('')
  const [showEmpty, setShowEmpty] = useState(true)
  const [mainDensity, setMainDensity] = useState<'comfortable'|'compact'>('comfortable')
  const sectionTargets = useMemo(() => (
    [
      { id: 'overview', label: 'Overview' },
      { id: 'languages', label: 'Languages Breakdown' },
      { id: 'repo', label: 'Repo' },
      { id: 'contributors-card', label: 'Contributors' },
      { id: 'commits-card', label: 'Commit History' },
      { id: 'vulnerabilities', label: 'Vulnerabilities' },
      { id: 'build', label: 'Build' },
      { id: 'cicd-card', label: 'CI/CD' },
      { id: 'findings', label: 'Findings' },
      { id: 'secrets-card', label: 'Published Secrets' },
      { id: 'codeql-card', label: 'CodeQL Findings' },
    ]
  ), [])
  function jumpToQuery(q: string) {
    const qq = (q || '').toLowerCase().trim()
    if (!qq) return
    const target = sectionTargets.find(t => t.label.toLowerCase().includes(qq))
    if (!target) return
    const el = document.getElementById(target.id)
    if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' })
  }
  function cardMuted(isEmpty: boolean): string {
    return (!showEmpty && isEmpty) ? 'opacity-70 bg-slate-50 border border-dashed' : ''
  }

  // Reusable column builders for fullscreen parity
  function contributorColumns(): ColumnDef<any>[] {
    return [
      { key: 'login', header: 'Login', sortable: true, filter: { type: 'text', getValue: (c) => String(c.display_name || c.login || '') }, render: (c) => (
        <span className="font-medium">{c.display_name || c.login}<span className="text-slate-500">{c.display_name ? ` (@${c.login})` : ''}</span></span>
      ) },
      { key: 'email', header: 'Email', sortable: true, filter: { type: 'text', getValue: (c) => String(c.email || '') } },
      { key: 'last_commit_at', header: 'Last Commit', sortable: true, render: (c) => c.last_commit_at ? new Date(c.last_commit_at).toLocaleString() : '—' },
      { key: 'commits_count', header: 'Commits', sortable: true, render: (c) => <span className="font-semibold">{c.commits_count ?? 0}</span> },
      { key: 'ask_ai', header: 'Ask AI', sortable: false, render: (c) => (
        <button type="button" className="text-xs px-2 py-0.5 border rounded" onClick={() => setContribAiCtx(c)}>Ask AI</button>
      ) },
    ]
  }

  function cicdColumns(): ColumnDef<any>[] {
    return [
      { key: 'workflow_name', header: 'Workflow', sortable: true, filter: { type: 'text', getValue: (r) => String(r.workflow_name || r.name || '') } },
      { key: 'event', header: 'Event', sortable: true, filter: { type: 'enum' } },
      { key: 'status', header: 'Status', sortable: true, filter: { type: 'enum', enumValues: ['queued','in_progress','completed'] } },
      { key: 'conclusion', header: 'Conclusion', sortable: true, filter: { type: 'enum', enumValues: ['success','failure','cancelled','skipped','neutral','timed_out','action_required','stale'] } },
      { key: 'branch', header: 'Branch', sortable: true, filter: { type: 'text', getValue: (r) => String(r.branch || '') } },
      { key: 'run_number', header: 'Run #', sortable: true, widthClass: 'w-20' },
      { key: 'actor_login', header: 'Actor', sortable: true, filter: { type: 'text', getValue: (r) => String(r.actor_login || '') } },
      { key: 'commit_sha', header: 'Commit', sortable: true, filter: { type: 'text', getValue: (r) => String(r.commit_sha || '') }, render: (r) => r.commit_sha ? r.commit_sha.substring(0,7) : '' },
      { key: 'created_at', header: 'Created', sortable: true, render: (r) => r.created_at ? new Date(r.created_at).toLocaleString() : '' },
      { key: 'html_url', header: 'Link', sortable: false, render: (r) => r.html_url ? <a href={r.html_url} target="_blank" rel="noreferrer" className="text-blue-600 underline">View</a> : <span className="text-slate-400">—</span> },
      { key: 'ask_ai', header: 'Ask AI', sortable: false, render: (r) => (
        <button type="button" className="text-xs px-2 py-0.5 border rounded" onClick={() => setCiAiCtx(r)}>Ask AI</button>
      ) },
    ]
  }

  function codeqlColumns(): ColumnDef<any>[] {
    return [
      {
        key: 'severity', header: 'Severity', sortable: true,
        filter: { type: 'enum', enumValues: ['critical','high','medium','low','info','unknown'], getValue: (it) => String(it.severity || 'unknown').toLowerCase() },
        render: (it) => (
          <span className={`text-xs px-2 py-0.5 rounded ${
            (it.severity||'').toLowerCase()==='critical' ? 'bg-red-600 text-white' :
            (it.severity||'').toLowerCase()==='high' ? 'bg-red-500 text-white' :
            (it.severity||'').toLowerCase()==='medium' ? 'bg-amber-400 text-black' :
            (it.severity||'').toLowerCase()==='low' ? 'bg-yellow-200 text-black' :
            (it.severity||'').toLowerCase()==='info' ? 'bg-blue-200 text-black' : 'bg-slate-200 text-black'}`}>{(it.severity||'unknown').toUpperCase()}</span>
        )
      },
      { key: 'rule_id', header: 'Rule', sortable: true, filter: { type: 'text', getValue: (it) => String(it.rule_id || '') } },
      { key: 'file', header: 'File', sortable: true, filter: { type: 'text', getValue: (it) => String(it.file || '') } },
      { key: 'line', header: 'Line', sortable: true },
      { key: 'message', header: 'Message', sortable: false, filter: { type: 'text', getValue: (it) => String(it.message || '') }, render: (it) => (<span title={it.message || ''}>{it.message || ''}</span>) },
      { key: 'help_uri', header: 'Docs', sortable: false, render: (it) => (it.help_uri ? <a className="text-blue-600 underline" href={it.help_uri} target="_blank" rel="noreferrer">Docs</a> : <span className="text-slate-400">—</span>) },
      { key: 'exploit', header: 'Exploit', sortable: false, render: (it) => {
        const k = String(it.rule_id||'')
        const st = cqExploitMap[k]?.status ?? null
        const cls = st===true ? 'bg-green-600 text-white' : st===false ? 'bg-slate-300 text-slate-900' : 'bg-slate-100 text-slate-800'
        const label = st===true ? 'True' : st===false ? 'False' : 'Unknown'
        return (
          <button type="button" className={`text-xs px-2 py-0.5 rounded border ${cls}`} onClick={() => openCqManage(k)} title="Manage exploit status">
            {label}
          </button>
        )
      } },
      { key: 'ask_ai', header: 'Ask AI', sortable: false, render: (it) => (
        <button type="button" className="text-xs px-2 py-0.5 border rounded" onClick={() => setCqAiCtx(it)}>Ask AI</button>
      ) },
    ]
  }

  function commitColumns(): ColumnDef<any>[] {
    return [
      { key: 'message', header: 'Message', sortable: true, filter: { type: 'text', getValue: (c) => String(c.message || '') }, render: (c) => <span className="truncate inline-block max-w-[40rem]" title={c.message || ''}>{c.message || '(no message)'}</span> },
      { key: 'committed_at', header: 'Committed At', sortable: true, render: (c) => new Date(c.committed_at).toLocaleString() },
      { key: 'author_login', header: 'Author', sortable: true, filter: { type: 'text', getValue: (c) => String(c.author_login || '') } },
      { key: 'author_email', header: 'Email', sortable: true, filter: { type: 'text', getValue: (c) => String(c.author_email || '') } },
      { key: 'sha', header: 'SHA', sortable: true, filter: { type: 'text', getValue: (c) => String(c.sha || '') }, render: (c) => c.sha?.substring(0,7) || '' },
      { key: 'url', header: 'Link', sortable: false, render: (c) => c.url ? <a href={c.url} target="_blank" rel="noreferrer" className="text-blue-600 underline">View</a> : <span className="text-slate-400">No link</span> },
      { key: 'ask_ai', header: 'Ask AI', sortable: false, render: (c) => (
        <button type="button" className="text-xs px-2 py-0.5 border rounded" onClick={() => setCommitAiCtx(c)}>Ask AI</button>
      ) },
    ]
  }

  // Phase 3: Group collapse/expand
  const [collapsed, setCollapsed] = useState<Record<'repo'|'vulnerabilities'|'build'|'findings', boolean>>({} as any)
  function toggleGroup(key: 'repo'|'vulnerabilities'|'build'|'findings') {
    setCollapsed(prev => ({ ...prev, [key]: !prev[key] }))
  }
  function expandAllGroups() { setCollapsed({} as any) }
  function collapseAllGroups() { setCollapsed({ repo: true, vulnerabilities: true, build: true, findings: true }) }

  // Fetch auth to determine admin role for masking/value visibility
  useEffect(() => {
    xhrGetJson(`${base}/auth/me`).then((d: any) => {
      const roles: string[] = d?.user?.roles || []
      const admin = !!(roles.includes('super_admin'))
      // In dev with authDisabled, treat as admin so value display is available
      setIsAdmin(admin || !!d?.authDisabled)
    }).catch(() => setIsAdmin(false)).finally(() => setAuthChecked(true))
  }, [base])
  const combinedSecrets = useMemo(() => {
    const a = (aiTokens || []).map((r) => ({
      source: 'genai',
      type: r.provider || 'genai',
      value: r.token,
      validation_status: r.validation_status,
      file_path: r.file_path,
      line_start: r.line_start,
      created_at: r.created_at,
    }))
    const b = (secretLeaks || []).map((r) => ({
      source: 'generic',
      type: r.detector || 'generic',
      value: r.secret, // present only when admin route used
      validation_status: r.validation_status,
      file_path: r.file_path,
      line_start: r.line_start,
      created_at: r.created_at,
    }))
    return [...a, ...b]
  }, [aiTokens, secretLeaks])

  // Load CI/CD runs for this project's repo (if URL is present)
  useEffect(() => {
    const repo = ownerRepoFromUrl(item?.repo_url || null)
    if (!repo) { setCiRuns([]); setCiError(null); return }
    const [owner, name] = repo.split('/')
    if (!owner || !name) { setCiRuns([]); setCiError(null); return }
    setCiLoading(true)
    setCiError(null)
    xhrGetJson(`${base}/api/repo/${encodeURIComponent(owner)}/${encodeURIComponent(name)}/actions/runs?per_page=50`)
      .then((d: any) => setCiRuns(d?.items || []))
      .catch((e: any) => setCiError(e?.message || 'Failed to load CI/CD runs'))
      .finally(() => setCiLoading(false))
  }, [base, item?.repo_url])

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
    xhrGetJson(`${base}/db/projects?select=id,uuid,name,repo_url,description,is_active,contributors_count,last_commit_at,primary_language,total_loc,stars,forks,created_at,updated_at&uuid=eq.${encodeURIComponent(uuid)}`)
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

  // Load GenAI tokens and generic secret leaks (admin route for value display)
  useEffect(() => {
    if (!item?.name) { setAiTokens([]); setSecretLeaks([]); return }
    if (!authChecked) return
    setSecretsLoading(true)
    setSecretsError(null)
    const aiSel = 'project_name,provider,token,repo_short,validation_status,file_path,line_start,line_end,created_at,updated_at'
    const aiUrl = `${base}/db/ai_tokens?select=${encodeURIComponent(aiSel)}&project_name=eq.${encodeURIComponent(item.name)}&order=created_at.desc`
    const secSelAdmin = 'project_name,repo_short,detector,rule_id,description,secret,file_path,line_start,line_end,confidence,validation_status,created_at,updated_at'
    const secSelPublic = 'project_name,repo_short,detector,rule_id,description,file_path,line_start,line_end,confidence,validation_status,created_at,updated_at'
    const secUrl = isAdmin
      ? `${base}/api/secret-leaks/admin?select=${encodeURIComponent(secSelAdmin)}&project_name=${encodeURIComponent(item.name)}&order=created_at.desc`
      : `${base}/api/secret-leaks?select=${encodeURIComponent(secSelPublic)}&project_name=${encodeURIComponent(item.name)}&order=created_at.desc`
    Promise.all([xhrGetJson(aiUrl), xhrGetJson(secUrl)])
      .then(([aRows, sData]) => {
        setAiTokens(aRows || [])
        setSecretLeaks(((sData?.items || []) as any[]))
      })
      .catch((e:any) => setSecretsError(e?.message || 'Failed to load secrets'))
      .finally(() => setSecretsLoading(false))
  }, [base, item?.name, isAdmin, authChecked])

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
    const limit = 500
    const offset = 0
    let url = `${base}/db/project_contributors?select=login,display_name,email,commits_count,last_commit_at&project_id=eq.${encodeURIComponent(uuid)}&order=${encodeURIComponent(order)}&limit=${limit}&offset=${offset}`
    if (contribSearch.trim()) {
      const q = contribSearch.trim()
      url += `&login=ilike.*${encodeURIComponent(q)}*`
    }
    xhrGetJson(url)
      .then((rows) => {
        const arr = rows || []
        setContributors(arr)
        setContribHasMore(arr.length >= limit)
      })
      .catch((e: any) => setErrorContrib(e?.message || 'Failed to load contributors'))
      .finally(() => setLoadingContrib(false))
  }, [base, uuid, contribSearch, contribSort])

  useEffect(() => {
    if (!uuid) return
    setLoadingCommits(true)
    setErrorCommits(null)
    const limit = 500
    const offset = 0
    let url = `${base}/db/project_commits?select=sha,author_login,author_email,committed_at,message,url&project_id=eq.${encodeURIComponent(uuid)}&order=committed_at.desc&limit=${limit}&offset=${offset}`
    if (commitSearch.trim()) {
      const q = commitSearch.trim()
      url += `&message=ilike.*${encodeURIComponent(q)}*`
    }
    xhrGetJson(url)
      .then((rows) => {
        const arr = rows || []
        setCommits(arr)
        setCommitHasMore(arr.length >= limit)
      })
      .catch((e: any) => setErrorCommits(e?.message || 'Failed to load commits'))
      .finally(() => setLoadingCommits(false))
  }, [base, uuid, commitSearch])

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
  useEffect(() => {
    // Default CodeQL repo input from project repo URL
    if (repo && !cqRepo) setCqRepo(repo.split('/').pop() as string)
  }, [repo])

  // Auto-load detected repos on initial load when project is ready
  useEffect(() => {
    if (item && item.uuid) {
      loadRepoOptions()
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [item?.uuid])

  async function loadRepoOptions() {
    if (!item) return
    setLoadingRepos(true)
    try {
      const url = `${base}/api/projects/${encodeURIComponent(item.uuid)}/codeql/repos`
      const data = await xhrGetJson(url)
      const rawOpts = ((data?.data || []) as string[]).filter(Boolean)
      // Prefer repos matching project's repo short name or project name
      const preferredRepo = (repoName || '').trim()
      const projectName = (item?.name || '').trim()
      let opts = rawOpts
      const prefKey = normalizeRepoKey(preferredRepo)
      const nameKey = normalizeRepoKey(projectName)
      if (prefKey) {
        const filtered = rawOpts.filter(o => normalizeRepoKey(o).includes(prefKey))
        if (filtered.length) opts = filtered
      } else if (nameKey) {
        const filtered = rawOpts.filter(o => normalizeRepoKey(o).includes(nameKey))
        if (filtered.length) opts = filtered
      }
      setRepoOptions(opts)
      // If no manual repo selected, prefer repo from project repo_url; otherwise try project name; finally pick first
      if (!cqRepo && opts.length > 0) {
        const preferredRepo = (repoName || '').trim()
        const projectName = (item?.name || '').trim()
        const pick = (() => {
          // Try exact case-insensitive match to repo from repo_url
          if (preferredRepo) {
            const lower = preferredRepo.toLowerCase()
            const found = opts.find(o => (o || '').toLowerCase() === lower)
            if (found) return found
            // Try normalized comparison
            const normPref = normalizeRepoKey(preferredRepo)
            const foundNorm = opts.find(o => normalizeRepoKey(o || '') === normPref)
            if (foundNorm) return foundNorm
            // Try normalized substring containment (handles dashes/underscores/casing)
            const foundContains = opts.find(o => normalizeRepoKey(o || '').includes(normPref))
            if (foundContains) return foundContains
          }
          // Try exact case-insensitive match to project name
          if (projectName) {
            const lowerName = projectName.toLowerCase()
            const foundByName = opts.find(o => (o || '').toLowerCase() === lowerName)
            if (foundByName) return foundByName
            const normName = normalizeRepoKey(projectName)
            const foundByNorm = opts.find(o => normalizeRepoKey(o || '') === normName)
            if (foundByNorm) return foundByNorm
            const foundByContains = opts.find(o => normalizeRepoKey(o || '').includes(normName))
            if (foundByContains) return foundByContains
          }
          // No match found: prefer keeping a meaningful value over defaulting to unrelated first option
          if (preferredRepo) return preferredRepo
          if (projectName) return projectName
          // Ultimately default to first detected
          return opts[0]
        })()
        setCqRepo(pick)
        // Fire and forget; no need to await here
        // eslint-disable-next-line @typescript-eslint/no-floating-promises
        loadCqFindingsForRepo(pick, 0)
        // Also load severity totals for this repo
        // eslint-disable-next-line @typescript-eslint/no-floating-promises
        loadCqTotals(pick)
      }
    } catch (e) {
      // ignore for now; keep manual input available
    } finally {
      setLoadingRepos(false)
    }
  }
  const scanHref = useMemo(() => {
    if (!item) return '#'
    const u = new URL('http://localhost:5173/')
    u.searchParams.set('project_uuid', item.uuid)
    if (repo) u.searchParams.set('repo', repo)
    return u.toString()
  }, [item, repo])

  async function loadCqFindings(page = cqPage) {
    if (!item) return
    if (!cqRepo && !repoName) { setCqError('Repo name is required'); return }
    setCqError(null)
    setCqLoading(true)
    try {
      const params = new URLSearchParams()
      // Prefer user-entered short name; fallback to detected repo short name
      const shortRepo = (cqRepo || repoName || '').trim()
      if (shortRepo) params.set('repo', shortRepo)
      if (cqSearch) params.set('search', cqSearch)
      if (cqSev.length) params.set('severity', cqSev.join(','))
      // Fetch up to 200 findings and page client-side via DataTable
      params.set('limit', String(200))
      params.set('offset', String(0))
      // Server-side sort not required when using DataTable
      const url = `${base}/api/projects/${encodeURIComponent(item.uuid)}/codeql/findings?${params.toString()}`
      const data = await xhrGetJson(url)
      setCqFindings(data?.data?.items || [])
      setCqTotal(Number(data?.data?.total || 0))
      setCqPage(page)
    } catch (e: any) {
      setCqError(e?.message || 'Failed to load CodeQL findings')
    } finally {
      setCqLoading(false)
    }
  }

  async function loadCqFindingsForRepo(shortRepo: string, page = 0) {
    if (!item) return
    const repoSel = (shortRepo || '').trim()
    if (!repoSel) { setCqError('Repo name is required'); return }
    setCqError(null)
    setCqLoading(true)
    try {
      const params = new URLSearchParams()
      params.set('repo', repoSel)
      if (cqSearch) params.set('search', cqSearch)
      if (cqSev.length) params.set('severity', cqSev.join(','))
      // Fetch up to 200 findings and page client-side via DataTable
      params.set('limit', String(200))
      params.set('offset', String(0))
      const url = `${base}/api/projects/${encodeURIComponent(item.uuid)}/codeql/findings?${params.toString()}`
      const data = await xhrGetJson(url)
      setCqFindings(data?.data?.items || [])
      setCqTotal(Number(data?.data?.total || 0))
      setCqPage(page)
    } catch (e: any) {
      setCqError(e?.message || 'Failed to load CodeQL findings')
    } finally {
      setCqLoading(false)
    }
  }

  // Load severity totals for the selected or inferred repo
  async function loadCqTotals(selectedRepo?: string) {
    if (!item) return
    const repoSel = (selectedRepo || cqRepo || repoName || '').trim()
    if (!repoSel) return
    try {
      const url = `${base}/api/projects/${encodeURIComponent(item.uuid)}/codeql/severity-totals?repo=${encodeURIComponent(repoSel)}`
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

  // Auto-load findings and totals when project/repo is available or filters change
  useEffect(() => {
    if (!item) return
    const repoSel = (cqRepo || repoName || '').trim()
    if (!repoSel) return
    // eslint-disable-next-line @typescript-eslint/no-floating-promises
    loadCqFindings(0)
    // eslint-disable-next-line @typescript-eslint/no-floating-promises
    loadCqTotals()
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [item?.uuid, cqRepo, repoName, cqSev, cqSort, cqDir, cqPageSize])

  // Compute Project Overview Exploit pill based on any True status among CodeQL and Terraform findings for this repo
  useEffect(() => {
    async function computeExploitPill() {
      try {
        if (!item?.uuid) { setOverviewExploit(null); return }
        const repoSel = (cqRepo || repoName || '').trim()
        if (!repoSel) { setOverviewExploit(null); return }
        setOverviewExploitLoading(true)
        // 1) CodeQL: check any rule_id status True among loaded findings
        const cqIds = Array.from(new Set((cqFindings || []).map((r: any) => String(r.rule_id || '').trim()).filter(Boolean)))
        if (cqIds.length) {
          try {
            const data = await xhrGetJson(`${base}/api/exploitability?type=codeql_rule&keys=${encodeURIComponent(cqIds.join(','))}`)
            const items = (data?.items || [])
            if (items.some((it: any) => it.exploit_available === true)) { setOverviewExploit(true); return }
          } catch { /* ignore and continue */ }
        }
        // 2) Terraform: fetch rule_ids for this project/repo from PostgREST then check statuses
        let tfIds: string[] = []
        try {
          const sel = 'rule_id'
          let url = `${base}/db/terraform_findings?select=${encodeURIComponent(sel)}&project_id=eq.${encodeURIComponent(item.uuid)}&order=created_at.desc&limit=200`
          if (repoSel) url += `&repo_short=eq.${encodeURIComponent(repoSel)}`
          const rows = await xhrGetJson(url)
          tfIds = Array.from(new Set((rows || []).map((r: any) => String(r.rule_id || '').trim()).filter(Boolean)))
        } catch { /* ignore */ }
        if (tfIds.length) {
          try {
            const data2 = await xhrGetJson(`${base}/api/exploitability?type=terraform_rule&keys=${encodeURIComponent(tfIds.join(','))}`)
            const items2 = (data2?.items || [])
            if (items2.some((it: any) => it.exploit_available === true)) { setOverviewExploit(true); return }
          } catch { /* ignore */ }
        }
        // 3) OSS: parse repo markdown to collect vuln IDs (CVE/GHSA) and check exploitability
        let ossCves: string[] = []
        let ossGhsas: string[] = []
        try {
          if (repoName) {
            const path = `/oss_reports/${repoName}/${repoName}_oss.md`
            const md = await xhrGetText(path)
            const ids = (() => {
              const lines = (md || '').split(/\r?\n/)
              let i = 0
              // find "## Vulnerabilities Found"
              while (i < lines.length && !/^##\s*Vulnerabilities Found/i.test(lines[i])) i++
              if (i >= lines.length) return [] as string[]
              // seek table header row starting with '|'
              while (i < lines.length && !/^\|/.test(lines[i])) i++
              if (i >= lines.length) return [] as string[]
              const header = lines[i++]
              if (i >= lines.length) return [] as string[]
              const sep = lines[i++]
              if (!/^\|\s*-/.test(sep)) return [] as string[]
              const headers = header.replace(/^\|/, '').replace(/\|$/, '').split('|').map(s=>s.trim())
              const vidx = headers.findIndex(h => /vulnerability id/i.test(h))
              if (vidx < 0) return [] as string[]
              const out: string[] = []
              while (i < lines.length && /^\|/.test(lines[i])) {
                const row = lines[i]
                const cells = row.replace(/^\|/, '').replace(/\|$/, '').split('|').map(s=>s.trim())
                if (vidx < cells.length) out.push(cells[vidx])
                i++
              }
              return out
            })()
            const norm = Array.from(new Set(ids.map(s => String(s || '').toUpperCase()).filter(Boolean)))
            ossCves = norm.filter(s => /^CVE-\d{4}-\d{4,}$/.test(s))
            ossGhsas = norm.filter(s => /^GHSA-/.test(s))
          }
        } catch { /* ignore */ }
        if (ossCves.length) {
          try {
            const d = await xhrGetJson(`${base}/api/exploitability?type=cve&keys=${encodeURIComponent(ossCves.join(','))}`)
            const items = (d?.items || [])
            if (items.some((it:any)=>it.exploit_available===true)) { setOverviewExploit(true); return }
          } catch { /* ignore */ }
        }
        if (ossGhsas.length) {
          try {
            const d = await xhrGetJson(`${base}/api/exploitability?type=ghsa&keys=${encodeURIComponent(ossGhsas.join(','))}`)
            const items = (d?.items || [])
            if (items.some((it:any)=>it.exploit_available===true)) { setOverviewExploit(true); return }
          } catch { /* ignore */ }
        }
        // If we had any IDs but none True, mark False; else Unknown
        if ((cqIds && cqIds.length) || (tfIds && tfIds.length) || (ossCves.length + ossGhsas.length > 0)) setOverviewExploit(false)
        else setOverviewExploit(null)
      } finally {
        setOverviewExploitLoading(false)
      }
    }
    // eslint-disable-next-line @typescript-eslint/no-floating-promises
    computeExploitPill()
  }, [base, item?.uuid, cqFindings, cqRepo, repoName])

  if (loading) return <div className="p-4">Loading…</div>
  if (error) return (
    <div className="p-4">
      <div className="text-red-700 bg-red-50 border border-red-200 rounded p-3 mb-3">{error}</div>
      <a href="/projects" className="text-blue-600 hover:underline">Back to Projects</a>
    </div>
  )
  if (!item || !form) return null

  // Build Ask AI context from currently visible tables (after client-side filtering)
  function buildAskAiContext(): AskAIContext {
    const overview = item ? {
      id: item.uuid, name: item.name, repo_url: item.repo_url, description: item.description,
      primary_language: item.primary_language, total_loc: item.total_loc, stars: item.stars, forks: item.forks,
      contributors_count: item.contributors_count, last_commit_at: item.last_commit_at,
    } : undefined
    const tables: AskAIContext['visibleTables'] = []
    // Languages table
    if (langs && langs.length >= 0) {
      tables.push({
        id: 'languages',
        name: 'Languages Breakdown',
        fields: [
          {key:'language',label:'Language'},
          {key:'loc',label:'LOC'},
          {key:'files',label:'Files'},
          {key:'bytes',label:'Bytes'},
          {key:'is_primary',label:'Primary'},
        ],
        rows: langs.map(l => ({ language: l.language, loc: l.loc ?? null, files: l.files ?? null, bytes: l.bytes, is_primary: l.is_primary })),
      })
    }
    // CodeQL Findings (already filtered client-side)
    if (cqFindings) {
      tables.push({
        id: 'codeql', name: 'CodeQL Findings',
        fields: [
          {key:'severity',label:'Severity'},
          {key:'rule_id',label:'Rule'},
          {key:'file',label:'File'},
          {key:'line',label:'Line'},
          {key:'message',label:'Message'},
        ],
        rows: cqFindings,
      })
    }
    // CI/CD
    if (ciRuns) {
      tables.push({
        id: 'cicd', name: 'CI/CD — GitHub Actions',
        fields: [
          {key:'workflow_name',label:'Workflow'},
          {key:'event',label:'Event'},
          {key:'status',label:'Status'},
          {key:'conclusion',label:'Conclusion'},
        ],
        rows: ciRuns,
      })
    }
    // Contributors
    if (contributors) {
      tables.push({
        id: 'contributors', name: 'Contributors',
        fields: [
          {key:'login',label:'Login'},
          {key:'email',label:'Email'},
          {key:'last_commit_at',label:'Last Commit'},
          {key:'commits_count',label:'Commits'},
        ],
        rows: contributors,
      })
    }
    // Commits
    if (commits) {
      tables.push({
        id: 'commits', name: 'Commit History',
        fields: [
          {key:'message',label:'Message'},
          {key:'author_login',label:'Author'},
          {key:'author_email',label:'Email'},
          {key:'committed_at',label:'Committed At'},
          {key:'sha',label:'SHA'},
        ],
        rows: commits,
      })
    }
    // Secrets (combined)
    if (combinedSecrets) {
      tables.push({
        id: 'secrets', name: 'Published Secrets (GenAI + Generic)',
        fields: [
          {key:'type',label:'Type'},
          {key:'file_path',label:'Path & File'},
          {key:'validation_status',label:'Validated'},
          {key:'value',label:'Value'},
          {key:'created_at',label:'Detected'},
        ],
        rows: combinedSecrets,
      })
    }
    return { overview, visibleTables: tables, selection }
  }

  function serializeCsvFromFields(fields: Array<{key:string;label:string}>, rows: any[]): string {
    const headers = fields.map(f => f.label)
    const out = [headers.join(',')]
    for (const r of rows) {
      const vals = fields.map(f => {
        const raw = (r as any)[f.key]
        const s = raw == null ? '' : String(raw)
        return '"' + s.replaceAll('"', '""') + '"'
      })
      out.push(vals.join(','))
    }
    return out.join('\n')
  }

  async function onAskAiRun() {
    const ctx = buildAskAiContext()
    setAskAiResponse('')
    setAskAiBusy(true)
    try {
      const answer = await askAI(askAiQuestion, ctx)
      // Simulate streaming output by chunking newlines
      const chunks = answer.split(/\n/)
      let acc = ''
      for (const ch of chunks) {
        acc += (acc ? '\n' : '') + ch
        setAskAiResponse(acc)
        // eslint-disable-next-line no-await-in-loop
        await new Promise(r => setTimeout(r, 15))
      }
    } catch (e: any) {
      setAskAiResponse(String(e?.message || e || 'Ask AI failed'))
    } finally {
      setAskAiBusy(false)
    }
  }

  async function openFullscreenTable(cfg: { id: string; name: string; fields?: Array<{key:string;label:string}>; columns?: ColumnDef<any>[]; rows: any[] }) {
    setFsConfig(cfg)
    setFsDensity('comfortable')
    setFsAiCtx(null)
    setFsManageKey(null)
    // Set exploit type and prefetch statuses for overlay
    const t: 'codeql_rule'|'terraform_rule'|'cve'|'ghsa'|null = cfg.id === 'codeql' ? 'codeql_rule' : (cfg.id === 'terraform' ? 'terraform_rule' : (cfg.id === 'oss' ? null : null))
    setFsExploitType(t)
    if (t === 'terraform_rule') {
      try {
        const ids = Array.from(new Set((cfg.rows||[]).map((r:any)=>String(r.rule_id||'').trim()).filter(Boolean)))
        if (ids.length) {
          const data = await xhrGetJson(`${base}/api/exploitability?type=terraform_rule&keys=${encodeURIComponent(ids.join(','))}`)
          const out: Record<string, { status: boolean | null; evidence: any[] }> = {}
          for (const it of (data?.items||[])) out[String(it.key)] = { status: it.exploit_available===true ? true : (it.exploit_available===false ? false : null), evidence: it.evidence||[] }
          setFsExploitMap(out)
        } else {
          setFsExploitMap({})
        }
      } catch {
        setFsExploitMap({})
      }
    } else if (t === 'codeql_rule') {
      // Seed overlay map from existing CodeQL map for quick status display
      const ids = Array.from(new Set((cfg.rows||[]).map((r:any)=>String(r.rule_id||'').trim()).filter(Boolean)))
      const out: Record<string, { status: boolean | null; evidence: any[] }> = {}
      for (const id of ids) {
        const m = cqExploitMap[id]
        if (m) out[id] = { status: m.status===true ? true : (m.status===false ? false : null), evidence: m.evidence||[] }
      }
      setFsExploitMap(out)
    } else if (cfg.id === 'oss') {
      try {
        const ids = Array.from(new Set((cfg.rows||[]).map((r:any)=>String(r.vuln_id||'').toUpperCase()).filter(Boolean)))
        const cves = ids.filter((s:string)=>/^CVE-\d{4}-\d{4,}$/.test(s))
        const ghsas = ids.filter((s:string)=>/^GHSA-/.test(s))
        const out: Record<string, { status: boolean | null; evidence: any[] }> = {}
        if (cves.length) {
          const data = await xhrGetJson(`${base}/api/exploitability?type=cve&keys=${encodeURIComponent(cves.join(','))}`)
          for (const it of (data?.items||[])) out[String(it.key).toUpperCase()] = { status: it.exploit_available===true ? true : (it.exploit_available===false ? false : null), evidence: it.evidence||[] }
        }
        if (ghsas.length) {
          const data2 = await xhrGetJson(`${base}/api/exploitability?type=ghsa&keys=${encodeURIComponent(ghsas.join(','))}`)
          for (const it of (data2?.items||[])) out[String(it.key).toUpperCase()] = { status: it.exploit_available===true ? true : (it.exploit_available===false ? false : null), evidence: it.evidence||[] }
        }
        setFsExploitMap(out)
      } catch {
        setFsExploitMap({})
      }
    } else {
      setFsExploitMap({})
    }
    setFsOpen(true)
  }

  function openFsManage(ruleId: string) {
    const key = String(ruleId||'')
    setFsManageKey(key)
    // Determine type and initial state
    let t = fsExploitType || (fsConfig?.id === 'codeql' ? 'codeql_rule' : (fsConfig?.id === 'terraform' ? 'terraform_rule' : null))
    if (!t && fsConfig?.id === 'oss') {
      const upper = key.toUpperCase()
      t = (/^CVE-\d{4}-\d{4,}$/.test(upper) ? 'cve' : 'ghsa') as any
    }
    setFsExploitType(t as any)
    let st: boolean | null = null
    let evidence: any[] = []
    if (t === 'codeql_rule') {
      const m = fsExploitMap[key] || cqExploitMap[key]
      st = m ? (m.status===true ? true : (m.status===false ? false : null)) : null
      evidence = m?.evidence || []
    } else if (t === 'terraform_rule') {
      const m = fsExploitMap[key]
      st = m ? (m.status===true ? true : (m.status===false ? false : null)) : null
      evidence = m?.evidence || []
    } else if (t === 'cve' || t === 'ghsa') {
      const m = fsExploitMap[key.toUpperCase()]
      st = m ? (m.status===true ? true : (m.status===false ? false : null)) : null
      evidence = m?.evidence || []
    }
    setFsManageStatus(st === true)
    setFsManageCitations((evidence||[]).map((e:any)=>String(e.url||'')).filter(Boolean).join('\n'))
  }

  async function saveFsManage() {
    if (!fsManageKey || !fsExploitType) return
    const urls = fsManageCitations.split(/\s+/).map((s: string)=>s.trim()).filter(Boolean)
    if (fsManageStatus && urls.length===0) return
    try {
      const evidence = urls.map((u: string) => ({ url: u }))
      await xhrPostJson(`${base}/api/exploitability`, { type: fsExploitType, key: fsManageKey, exploit_available: !!fsManageStatus, evidence })
      const data = await xhrGetJson(`${base}/api/exploitability?type=${encodeURIComponent(fsExploitType)}&key=${encodeURIComponent(fsManageKey)}`)
      const it = (data?.items||[])[0]
      if (it) {
        setFsExploitMap((prev) => ({ ...prev, [String(it.key)]: { status: it.exploit_available===true ? true : (it.exploit_available===false ? false : null), evidence: it.evidence||[] } }))
        if (fsExploitType === 'codeql_rule') {
          // keep in sync with main CodeQL map
          setCqExploitMap((prev) => ({ ...prev, [String(it.key)]: { status: it.exploit_available===true ? true : (it.exploit_available===false ? false : null), evidence: it.evidence||[] } }))
        }
      }
      setFsManageKey(null)
    } catch {
      // ignore
    }
  }

  // Keep underlying logic for Add/Delete but do not expose UI
  function addFsRow() {
    if (!fsConfig) return
    const empty: any = {}
    for (const f of fsEffectiveFields) empty[f.key] = ''
    setFsConfig({ ...fsConfig, rows: [...fsConfig.rows, empty] })
  }
  function removeFsRow(index: number) {
    if (!fsConfig) return
    const rows = fsConfig.rows.slice(0, index).concat(fsConfig.rows.slice(index + 1))
    setFsConfig({ ...fsConfig, rows })
  }

  function downloadCsv(name: string, csv: string) {
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `${name}.csv`
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
  }

  // Smoke tests exposed on window for manual invocation
  ;(window as any).runProjectDetailSmokeTests = function runSmokeTests() {
    try {
      // CSV test
      const f = [{key:'a',label:'A'},{key:'b',label:'B'}]
      const r = [{a:'x,y',b:'"quoted"'},{a:null,b:undefined},{a:'multi\nline',b:'ok'}]
      const csv = serializeCsvFromFields(f, r)
      if (!csv.includes('"x,y"') || !csv.includes('""quoted""') || !csv.includes('multi\nline')) throw new Error('CSV serialization failed')
      // Fullscreen mount test
      openFullscreenTable({ id: 'test', name: 'Test', fields: f as any, rows: r })
      setTimeout(() => setFsOpen(false), 50)
      // Ask AI context test
      const ctx = buildAskAiContext()
      if (!ctx || !Array.isArray(ctx.visibleTables)) throw new Error('AskAIContext invalid')
      // eslint-disable-next-line no-console
      console.log('runProjectDetailSmokeTests passed')
    } catch (e) {
      // eslint-disable-next-line no-console
      console.error('runProjectDetailSmokeTests failed:', e)
    }
  }

  return (
    <div className="auditor-dashboard min-h-screen bg-gradient-to-b from-slate-100 to-slate-200 text-slate-900">
      <header className="flex items-center justify-between p-4 border-b bg-white sticky top-0">
        <nav className="text-sm"><a href="/projects" className="text-blue-600 hover:underline">Projects</a> /</nav>
        <div className="flex items-center gap-2">
          <a href={scanHref} className="bg-amber-500 text-white px-3 py-1 rounded">Scan Repo</a>
          <button onClick={save} disabled={saving} className="bg-blue-600 text-white px-3 py-1 rounded disabled:opacity-50">{saving ? 'Saving…' : 'Save'}</button>
        </div>
      </header>
      <main className="p-4">
        <div className="max-w-7xl mx-auto grid grid-cols-1 lg:grid-cols-[1fr_18rem] gap-4">
          <div className={`space-y-4 ${mainDensity==='compact' ? 'text-xs' : 'text-sm'}`}>
            <div id="overview" className="bg-white p-4 rounded shadow-sm">
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
            <div className="text-sm md:col-span-1">
              <div className="mb-1 flex items-center gap-2">Exploit
                <button type="button" className="inline-flex items-center justify-center w-5 h-5 text-xs border rounded bg-slate-100 hover:bg-slate-200" title="Exploit types help" onClick={() => setExploitHelpOpen(true)}>?</button>
              </div>
              {(() => {
                const st = overviewExploit
                const cls = st===true ? 'bg-green-600 text-white' : st===false ? 'bg-slate-300 text-slate-900' : 'bg-slate-100 text-slate-800'
                const label = st===true ? 'True' : st===false ? 'False' : (overviewExploitLoading ? 'Checking…' : 'Unknown')
                return (
                  <span className={`inline-block text-xs px-2 py-0.5 rounded border ${cls}`} title="Any finding in this repo marked as exploit available">
                    {label}
                  </span>
                )
              })()}
              {item?.uuid ? (
                <ExploitTypeGrid projectId={item.uuid} />
              ) : null}
            </div>
            {(typeof item?.contributors_count !== 'undefined' || item?.last_commit_at || typeof item?.stars === 'number' || typeof item?.forks === 'number') ? (
              <div className="text-sm text-slate-600 md:col-span-2">
                <span className="mr-4">Contributors: <strong>{item?.contributors_count ?? 0}</strong></span>
                {item?.last_commit_at ? <span>Last commit: <strong>{new Date(item.last_commit_at).toLocaleString()}</strong></span> : null}
                {(typeof item?.stars === 'number' || typeof item?.forks === 'number') ? (
                  <span className="ml-4">Stars/Forks: <strong>{typeof item?.stars === 'number' ? item.stars.toLocaleString() : '—'}</strong> / <strong>{typeof item?.forks === 'number' ? item.forks.toLocaleString() : '—'}</strong></span>
                ) : null}
              </div>
            ) : null}
          </div>
            </div>

        {/* Top controls (search + show-empty visual styling) */}
        <div className="bg-white p-3 rounded shadow-sm">
          <div className="flex flex-wrap items-center gap-2">
            <div className="flex items-center gap-2">
              <input
                className="border rounded px-2 py-1 w-64"
                placeholder="Search sections (e.g., Secrets, CodeQL, CI/CD...)"
                value={topQuery}
                onChange={e => setTopQuery(e.target.value)}
                onKeyDown={e => { if (e.key === 'Enter') jumpToQuery(topQuery) }}
              />
              <button className="px-2 py-1 border rounded bg-slate-100 hover:bg-slate-200" onClick={() => jumpToQuery(topQuery)}>Go</button>
            </div>
            <label className="flex items-center gap-2 text-sm">
              <input type="checkbox" checked={showEmpty} onChange={e=>setShowEmpty(e.target.checked)} />
              <span>Show empty (normal style)</span>
            </label>
            <label className="flex items-center gap-2 text-sm">
              <span>Density</span>
              <select className="border rounded px-2 py-1" value={mainDensity} onChange={e=>setMainDensity(e.target.value as any)}>
                <option value="comfortable">Comfortable</option>
                <option value="compact">Compact</option>
              </select>
            </label>
            <div className="ml-auto flex items-center gap-2">
              <button className="px-2 py-1 border rounded bg-slate-100 hover:bg-slate-200" onClick={collapseAllGroups}>Collapse All</button>
              <button className="px-2 py-1 border rounded bg-slate-100 hover:bg-slate-200" onClick={expandAllGroups}>Expand All</button>
            </div>
          </div>
        </div>

        {/* Project KPIs */}
        <ChartHost
          datasetKey={`project.kpis.${uuid}`}
          title="Project KPIs"
          adapter={ProjectKPIAdapter}
          defaultType="kpis"
          availableTypes={["kpis","bar","bullet"]}
          params={{ projectId: uuid }}
          timeRangeOptions={[]}
        />

        {/* Languages Breakdown — placed right after Overview */}
        <div id="languages" className={`bg-white p-4 rounded shadow-sm ${cardMuted((langs||[]).length===0)}`}>
          <div className="flex items-center justify-between mb-2">
            <h2 className="font-medium">Languages Breakdown</h2>
            <div className="text-xs text-slate-600">{langs?.length || 0} rows</div>
          </div>
          <ChartHost
            datasetKey={`project.languages.${uuid}`}
            title="Languages Breakdown"
            adapter={ProjectLanguagesAdapter}
            defaultType="donut"
            availableTypes={["donut","pie","treemap","sunburst","bar"]}
            params={{ projectId: uuid }}
            timeRangeOptions={[]}
          />
        </div>

        {/* Repo group */}
        <div id="repo" className="px-1 pt-1 text-xs uppercase tracking-wide text-slate-500 flex items-center justify-between">
          <span>Repo</span>
          <button className="text-xs px-2 py-0.5 border rounded" onClick={() => toggleGroup('repo')}>{collapsed.repo ? 'Expand' : 'Collapse'}</button>
        </div>
        <div className={`grid grid-cols-1 md:grid-cols-2 gap-4 ${collapsed.repo ? 'hidden' : ''}`}>
        <div id="contributors-card" className={`bg-white p-4 rounded shadow-sm ${cardMuted((contributors||[]).length===0)} ${collapsed.repo ? 'hidden' : ''}`}>
          <div className="flex items-center justify-between mb-2">
            <h2 className="font-medium">Contributors</h2>
            <div className="flex items-center gap-2 text-xs text-slate-600">
              <span>{contributors?.length || 0} rows</span>
              <button
                className="px-2 py-1 border rounded bg-slate-100 hover:bg-slate-200"
                onClick={() => openFullscreenTable({ id: 'contributors', name: 'Contributors', columns: contributorColumns(), rows: contributors })}
              >
                Fullscreen
              </button>
            </div>
          </div>
          <div className="flex flex-wrap items-center gap-2 mb-3 text-sm">
            <label className="flex items-center gap-2">
              <span>Sort:</span>
              <select className="border rounded px-2 py-1" value={contribSort} onChange={(e) => { setContribSort((e.target.value as 'commits'|'recent')); }}>
                <option value="commits">Most commits</option>
                <option value="recent">Most recent</option>
              </select>
            </label>
          </div>
          {loadingContrib ? (
            <div className="text-sm text-slate-600">Loading…</div>
          ) : errorContrib ? (
            <div className="text-sm text-red-700">{errorContrib}</div>
          ) : (
            (() => {
              const columns: ColumnDef<any>[] = [
                { key: 'login', header: 'Login', sortable: true, filter: { type: 'text', getValue: (c) => String(c.display_name || c.login || '') }, render: (c) => (
                  <span className="font-medium">{c.display_name || c.login}<span className="text-slate-500">{c.display_name ? ` (@${c.login})` : ''}</span></span>
                ) },
                { key: 'email', header: 'Email', sortable: true, filter: { type: 'text', getValue: (c) => String(c.email || '') } },
                { key: 'last_commit_at', header: 'Last Commit', sortable: true, render: (c) => c.last_commit_at ? new Date(c.last_commit_at).toLocaleString() : '—' },
                { key: 'commits_count', header: 'Commits', sortable: true, render: (c) => <span className="font-semibold">{c.commits_count ?? 0}</span> },
                { key: 'ask_ai', header: 'Ask AI', sortable: false, render: (c) => (
                  <button type="button" className="text-xs px-2 py-0.5 border rounded" onClick={() => setContribAiCtx(c)}>Ask AI</button>
                ) },
              ]
              return (
                <>
                  <DataTable
                    data={contributors}
                    columns={columns}
                    defaultPageSize={10}
                    filterKeys={['login','display_name','email']}
                  />
                  {contribAiCtx && !fsOpen && (
                    <div className="mt-3">
                      <AiAssistantPanel
                        target="cicd"
                        projectId={item.uuid}
                        repoShort={repoName || undefined}
                        context={contribAiCtx}
                        onClose={() => setContribAiCtx(null)}
                      />
                    </div>
                  )}
                </>
              )
            })()
          )}
        </div>

        <div id="commits-card" className={`bg-white p-4 rounded shadow-sm ${cardMuted((commits||[]).length===0)} ${collapsed.repo ? 'hidden' : ''}`}>
          <div className="flex items-center justify-between mb-2">
            <h2 className="font-medium">Commit History</h2>
            <div className="flex items-center gap-2 text-xs text-slate-600">
              <span>{commits?.length || 0} rows</span>
              <button
                className="px-2 py-1 border rounded bg-slate-100 hover:bg-slate-200"
                onClick={() => openFullscreenTable({ id: 'commits', name: 'Commit History', columns: commitColumns(), rows: commits })}
              >
                Fullscreen
              </button>
            </div>
          </div>
          {loadingCommits ? (
            <div className="text-sm text-slate-600">Loading…</div>
          ) : errorCommits ? (
            <div className="text-sm text-red-700">{errorCommits}</div>
          ) : commits.length === 0 ? (
            <div className="text-sm text-slate-600">No commits found.</div>
          ) : (
            (() => {
              const columns: ColumnDef<any>[] = [
                { key: 'message', header: 'Message', sortable: true, filter: { type: 'text', getValue: (c) => String(c.message || '') }, render: (c) => <span className="truncate inline-block max-w-[40rem]" title={c.message || ''}>{c.message || '(no message)'}</span> },
                { key: 'committed_at', header: 'Committed At', sortable: true, render: (c) => new Date(c.committed_at).toLocaleString() },
                { key: 'author_login', header: 'Author', sortable: true, filter: { type: 'text', getValue: (c) => String(c.author_login || '') } },
                { key: 'author_email', header: 'Email', sortable: true, filter: { type: 'text', getValue: (c) => String(c.author_email || '') } },
                { key: 'sha', header: 'SHA', sortable: true, filter: { type: 'text', getValue: (c) => String(c.sha || '') }, render: (c) => c.sha?.substring(0,7) || '' },
                { key: 'url', header: 'Link', sortable: false, render: (c) => c.url ? <a href={c.url} target="_blank" rel="noreferrer" className="text-blue-600 underline">View</a> : <span className="text-slate-400">No link</span> },
                { key: 'ask_ai', header: 'Ask AI', sortable: false, render: (c) => (
                  <button type="button" className="text-xs px-2 py-0.5 border rounded" onClick={() => setCommitAiCtx(c)}>Ask AI</button>
                ) },
              ]
              return (
                <>
                  <DataTable
                    data={commits}
                    columns={columns}
                    defaultPageSize={10}
                    filterKeys={['message','author_login','author_email','sha']}
                  />
                  {commitAiCtx && !fsOpen && (
                    <div className="mt-3">
                      <AiAssistantPanel
                        target="cicd"
                        projectId={item.uuid}
                        repoShort={repoName || undefined}
                        context={commitAiCtx}
                        onClose={() => setCommitAiCtx(null)}
                      />
                    </div>
                  )}
                </>
              )
            })()
          )}
        </div>
        </div>

        {/* Vulnerabilities group */}
        <div id="vulnerabilities" className="px-1 pt-1 text-xs uppercase tracking-wide text-slate-500 flex items-center justify-between">
          <span>Vulnerabilities</span>
          <button className="text-xs px-2 py-0.5 border rounded" onClick={() => toggleGroup('vulnerabilities')}>{collapsed.vulnerabilities ? 'Expand' : 'Collapse'}</button>
        </div>
        <div className={`${collapsed.vulnerabilities ? 'hidden' : ''}`}>
          <OssVulnTables repoName={repoName} projectId={item.uuid} onRequestFullscreen={openFullscreenTable} overlayActive={fsOpen} />
        </div>

        {/* Build group */}
        <div id="build" className="px-1 pt-1 text-xs uppercase tracking-wide text-slate-500 flex items-center justify-between">
          <span>Build</span>
          <button className="text-xs px-2 py-0.5 border rounded" onClick={() => toggleGroup('build')}>{collapsed.build ? 'Expand' : 'Collapse'}</button>
        </div>
        <div className={`grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4 ${collapsed.build ? 'hidden' : ''}`}>
          <TerraformFindings projectId={item.uuid} repoName={repoName} onRequestFullscreen={openFullscreenTable} overlayActive={fsOpen} />

          <BinariesTable projectId={item.uuid} repoName={repoName} onRequestFullscreen={openFullscreenTable} />

          {/* CI/CD: GitHub Actions recent runs */}
          <div id="cicd-card" className={`bg-white p-4 rounded shadow-sm ${cardMuted((ciRuns||[]).length===0)}`}>
          <div className="flex items-center justify-between mb-2">
            <h2 className="font-medium">CI/CD</h2>
            <div className="text-xs text-slate-600">GitHub Actions recent runs</div>
            <div className="text-xs text-slate-600 ml-auto mr-3">{ciRuns?.length || 0} rows</div>
            <div className="flex items-center gap-2">
              <button
                className="px-2 py-1 border rounded bg-slate-100 hover:bg-slate-200"
                onClick={() => openFullscreenTable({
                  id:'cicd',
                  name:'CI/CD — GitHub Actions',
                  columns: cicdColumns(),
                  rows: ciRuns
                })}
              >
                Fullscreen
              </button>
              <button
                className="px-2 py-1 border rounded bg-slate-100 hover:bg-slate-200"
                onClick={() => downloadCsv('cicd', serializeCsvFromFields(
                  [{key:'workflow_name',label:'Workflow'},{key:'event',label:'Event'},{key:'status',label:'Status'},{key:'conclusion',label:'Conclusion'}],
                  ciRuns
                ))}
              >
                Export CSV
              </button>
            </div>
          </div>
          {ciError && <div className="text-sm text-red-700">{ciError}</div>}
          {ciLoading ? (
            <div className="text-sm text-slate-600">Loading…</div>
          ) : (
            (() => {
              if (!ciRuns || ciRuns.length === 0) return <div className="text-sm text-slate-600">No workflow runs found.</div>
              const columns: ColumnDef<any>[] = [
                { key: 'workflow_name', header: 'Workflow', sortable: true, filter: { type: 'text', getValue: (r) => String(r.workflow_name || r.name || '') } },
                { key: 'event', header: 'Event', sortable: true, filter: { type: 'enum' } },
                { key: 'status', header: 'Status', sortable: true, filter: { type: 'enum', enumValues: ['queued','in_progress','completed'] } },
                { key: 'conclusion', header: 'Conclusion', sortable: true, filter: { type: 'enum', enumValues: ['success','failure','cancelled','skipped','neutral','timed_out','action_required','stale'] } },
                { key: 'branch', header: 'Branch', sortable: true, filter: { type: 'text', getValue: (r) => String(r.branch || '') } },
                { key: 'run_number', header: 'Run #', sortable: true, widthClass: 'w-20' },
                { key: 'actor_login', header: 'Actor', sortable: true, filter: { type: 'text', getValue: (r) => String(r.actor_login || '') } },
                { key: 'commit_sha', header: 'Commit', sortable: true, filter: { type: 'text', getValue: (r) => String(r.commit_sha || '') }, render: (r) => r.commit_sha ? r.commit_sha.substring(0,7) : '' },
                { key: 'created_at', header: 'Created', sortable: true, render: (r) => r.created_at ? new Date(r.created_at).toLocaleString() : '' },
                { key: 'html_url', header: 'Link', sortable: false, render: (r) => r.html_url ? <a href={r.html_url} target="_blank" rel="noreferrer" className="text-blue-600 underline">View</a> : <span className="text-slate-400">—</span> },
                { key: 'ask_ai', header: 'Ask AI', sortable: false, render: (r) => (
                  <button type="button" className="text-xs px-2 py-0.5 border rounded" onClick={() => setCiAiCtx(r)}>Ask AI</button>
                ) },
              ]
              return (
                <>
                  <DataTable
                    data={ciRuns}
                    columns={columns}
                    defaultPageSize={10}
                    filterKeys={['workflow_name','event','status','conclusion','branch','actor_login','commit_sha']}
                  />
                  {ciAiCtx && !fsOpen && (
                    <div className="mt-3">
                      <AiAssistantPanel
                        target="cicd"
                        projectId={item.uuid}
                        repoShort={repoName || undefined}
                        context={ciAiCtx}
                        onClose={() => setCiAiCtx(null)}
                      />
                    </div>
                  )}
                </>
              )
            })()
          )}
        </div>
        </div>

        <div id="findings" className="px-1 pt-1 text-xs uppercase tracking-wide text-slate-500 flex items-center justify-between">
          <span>Findings</span>
          <button className="text-xs px-2 py-0.5 border rounded" onClick={() => toggleGroup('findings')}>{collapsed.findings ? 'Expand' : 'Collapse'}</button>
        </div>
        <div className={`grid grid-cols-1 md:grid-cols-2 gap-4 ${collapsed.findings ? 'hidden' : ''}`}>
        <div id="secrets-card" className={`bg-white p-4 rounded shadow-sm ${cardMuted((combinedSecrets||[]).length===0)} ${collapsed.findings ? 'hidden' : ''}`}>
          <div className="flex items-center justify-between mb-2">
            <h2 className="font-medium">Published Secrets (GenAI + Generic)</h2>
            <div className="flex items-center gap-3 text-xs text-slate-600">
              <span>Values shown only for admins</span>
              <span className="ml-2">{combinedSecrets?.length || 0} rows</span>
              <button
                type="button"
                className="px-2 py-1 border rounded bg-slate-100 hover:bg-slate-200"
                title="Fullscreen"
                onClick={() => {
                  const columns: ColumnDef<any>[] = [
                    { key: 'type', header: 'Type', sortable: true, filter: { type: 'enum' } },
                    { key: 'file_path', header: 'Path & File', sortable: true, filter: { type: 'text', getValue: (r) => String(r.file_path || '') }, render: (r) => (
                      <span title={r.file_path || ''}>{r.file_path}{typeof r.line_start === 'number' ? `:${r.line_start}` : ''}</span>
                    ) },
                    { key: 'validation_status', header: 'Validated', sortable: true, filter: { type: 'enum', enumValues: ['valid','invalid','error','unknown'], getValue: (r) => String(r.validation_status || 'unknown').toLowerCase() }, render: (r) => (r.validation_status || '').toUpperCase() || 'UNKNOWN' },
                    { key: 'value', header: 'Value', sortable: false, filter: { type: 'text', disabled: !isAdmin, getValue: (r) => String(r.value || '') }, render: (r) => (
                      <span className="inline-flex items-center gap-2">
                        <span>{(() => { const s = (r.value || '').toString(); if (!s) return '••••'; if (isAdmin && showValues) return s; return `••••${s.slice(-4)}`; })()}</span>
                      </span>
                    ) },
                    { key: 'created_at', header: 'Detected', sortable: true, render: (r) => r.created_at ? new Date(r.created_at).toLocaleString() : '' },
                    { key: 'ask_ai', header: 'Ask AI', sortable: false, render: (r) => (
                      <button type="button" className="text-xs px-2 py-0.5 border rounded" onClick={() => setSecretAiCtx(r)}>Ask AI</button>
                    ) },
                  ]
                  openFullscreenTable({ id:'secrets', name:'Published Secrets', columns, rows: combinedSecrets })
                }}
              >
                Fullscreen
              </button>
              <button
                type="button"
                className="px-2 py-1 border rounded bg-slate-100 hover:bg-slate-200"
                title="Export CSV"
                onClick={() => downloadCsv('secrets', serializeCsvFromFields(
                  [
                    {key:'type',label:'Type'},{key:'file_path',label:'Path & File'},{key:'validation_status',label:'Validated'},
                    {key:'value',label:'Value'},{key:'created_at',label:'Detected'}
                  ],
                  combinedSecrets
                ))}
              >
                Export CSV
              </button>
              {isAdmin && (
                <button
                  type="button"
                  className="px-2 py-1 border rounded bg-slate-100 hover:bg-slate-200"
                  onClick={() => setShowValues(v => !v)}
                >
                  {showValues ? 'Hide values' : 'Show values'}
                </button>
              )}
            </div>
          </div>
          {secretsLoading ? (
            <div className="text-sm text-slate-600">Loading…</div>
          ) : secretsError ? (
            <div className="text-sm text-red-700">{secretsError}</div>
          ) : (combinedSecrets || []).length === 0 ? (
            <div className="text-sm text-slate-600">None Found</div>
          ) : (
            (() => {
              async function copyValue(v?: string) {
                if (!v) return
                try {
                  if (navigator.clipboard?.writeText) await navigator.clipboard.writeText(v)
                  else {
                    const ta = document.createElement('textarea')
                    ta.value = v
                    document.body.appendChild(ta)
                    ta.select()
                    document.execCommand('copy')
                    document.body.removeChild(ta)
                  }
                } catch {
                  // ignore
                }
              }
              function maskValue(v?: string): string {
                const s = (v || '').toString()
                if (!s) return '••••'
                if (isAdmin && showValues) return s
                const last4 = s.slice(-4)
                return `••••${last4}`
              }
              const columns: ColumnDef<any>[] = [
                { key: 'type', header: 'Type', sortable: true, filter: { type: 'enum' } },
                { key: 'file_path', header: 'Path & File', sortable: true, filter: { type: 'text', getValue: (r) => String(r.file_path || '') }, render: (r) => (
                  <span title={r.file_path || ''}>{r.file_path}{typeof r.line_start === 'number' ? `:${r.line_start}` : ''}</span>
                ) },
                { key: 'validation_status', header: 'Validated', sortable: true, filter: { type: 'enum', enumValues: ['valid','invalid','error','unknown'], getValue: (r) => String(r.validation_status || 'unknown').toLowerCase() }, render: (r) => (r.validation_status || '').toUpperCase() || 'UNKNOWN' },
                { key: 'value', header: 'Value', sortable: false, filter: { type: 'text', disabled: !isAdmin, getValue: (r) => String(r.value || '') }, render: (r) => (
                  <span className="inline-flex items-center gap-2">
                    <span>{maskValue(r.value)}</span>
                    {isAdmin && r.value ? (
                      <button
                        type="button"
                        className="px-1 py-0.5 text-xs border rounded bg-slate-100 hover:bg-slate-200"
                        title="Copy value"
                        onClick={() => copyValue(r.value)}
                      >
                        Copy
                      </button>
                    ) : null}
                  </span>
                ) },
                { key: 'created_at', header: 'Detected', sortable: true, render: (r) => r.created_at ? new Date(r.created_at).toLocaleString() : '' },
                { key: 'ask_ai', header: 'Ask AI', sortable: false, render: (r) => (
                  <button type="button" className="text-xs px-2 py-0.5 border rounded" onClick={() => setSecretAiCtx(r)}>Ask AI</button>
                ) },
              ]
              return (
                <>
                  <DataTable
                    data={combinedSecrets}
                    columns={columns}
                    defaultPageSize={10}
                    filterKeys={['type','file_path','validation_status','value']}
                  />
                  {secretAiCtx && !fsOpen && (
                    <div className="mt-3">
                      <AiAssistantPanel
                        target="secret"
                        projectId={item.uuid}
                        repoShort={repoName || undefined}
                        context={secretAiCtx}
                        onClose={() => setSecretAiCtx(null)}
                      />
                    </div>
                  )}
                </>
              )
            })()
          )}
        </div>

        <div id="codeql-card" className={`bg-white p-4 rounded shadow-sm ${cardMuted((cqFindings||[]).length===0)} ${collapsed.findings ? 'hidden' : ''}`}>
          <div className="flex items-center justify-between mb-2">
            <h2 className="font-medium">CodeQL Findings</h2>
            <div className="text-xs text-slate-600">Latest successful scan</div>
            <div className="text-xs text-slate-600 ml-auto mr-3">{cqFindings?.length || 0} rows</div>
            <div className="flex items-center gap-2">
              <button
                className="px-2 py-1 border rounded bg-slate-100 hover:bg-slate-200"
                onClick={() => openFullscreenTable({
                  id:'codeql',
                  name:'CodeQL Findings',
                  columns: codeqlColumns(),
                  rows: cqFindings
                })}
              >
                Fullscreen
              </button>
              <button
                className="px-2 py-1 border rounded bg-slate-100 hover:bg-slate-200"
                onClick={() => downloadCsv('codeql', serializeCsvFromFields(
                  [{key:'severity',label:'Severity'},{key:'rule_id',label:'Rule'},{key:'file',label:'File'},{key:'line',label:'Line'},{key:'message',label:'Message'}],
                  cqFindings
                ))}
              >
                Export CSV
              </button>
            </div>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-4 gap-3 mb-3 text-sm">
            <label className="flex flex-col">
              <span className="text-xs text-slate-600">Repo (short name)</span>
              <input className="border rounded px-2 py-1" value={cqRepo} onChange={e => setCqRepo(e.target.value)} placeholder={repoName || 'e.g. oscp'} />
            </label>
            {(repoOptions.length > 1) && (
              <label className="flex flex-col">
                <span className="text-xs text-slate-600">Detected repos</span>
                <div className="flex items-center gap-2">
                  <select className="border rounded px-2 py-1 min-w-[12rem]" value={(() => { const lc = (cqRepo||'').toLowerCase(); const match = repoOptions.find(r => (r||'').toLowerCase()===lc); return match || ''; })()} onChange={e => setCqRepo(e.target.value)}>
                    <option value="">{loadingRepos ? 'Loading…' : 'Select a repo'}</option>
                    {repoOptions.map(r => <option key={r} value={r}>{r}</option>)}
                  </select>
                  <button className="px-2 py-1 bg-slate-200 rounded" onClick={loadRepoOptions} disabled={loadingRepos}>Refresh</button>
                </div>
              </label>
            )}
            <div className="flex items-end gap-2">
              <button className="px-3 py-1 bg-slate-200 rounded" onClick={() => loadCqFindings(0)} disabled={cqLoading}>Refresh</button>
              <button className="px-3 py-1 bg-slate-100 rounded" onClick={() => { setCqSearch(''); setCqSev([...defaultSeverities]); setCqSort('severity'); setCqDir('desc'); setCqPage(0); setCqFindings([]); setCqTotal(0); }}>Reset</button>
            </div>
          </div>
          {/* Severity totals with click-to-filter */}
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
          {(() => {
            const columns: ColumnDef<any>[] = [
              {
                key: 'severity',
                header: 'Severity',
                sortable: true,
                filter: { type: 'enum', enumValues: ['critical','high','medium','low','info','unknown'], getValue: (it) => String(it.severity || 'unknown').toLowerCase() },
                render: (it) => (
                  <span className={`text-xs px-2 py-0.5 rounded ${
                    (it.severity||'').toLowerCase()==='critical' ? 'bg-red-600 text-white' :
                    (it.severity||'').toLowerCase()==='high' ? 'bg-red-500 text-white' :
                    (it.severity||'').toLowerCase()==='medium' ? 'bg-amber-400 text-black' :
                    (it.severity||'').toLowerCase()==='low' ? 'bg-yellow-200 text-black' :
                    (it.severity||'').toLowerCase()==='info' ? 'bg-blue-200 text-black' : 'bg-slate-200 text-black'}`}>{(it.severity||'unknown').toUpperCase()}</span>
                )
              },
              { key: 'rule_id', header: 'Rule', sortable: true, filter: { type: 'text', getValue: (it) => String(it.rule_id || '') } },
              { key: 'file', header: 'File', sortable: true, filter: { type: 'text', getValue: (it) => String(it.file || '') } },
              { key: 'line', header: 'Line', sortable: true },
              { key: 'message', header: 'Message', sortable: false, filter: { type: 'text', getValue: (it) => String(it.message || '') }, render: (it) => (<span title={it.message || ''}>{it.message || ''}</span>) },
              { key: 'help_uri', header: 'Docs', sortable: false, render: (it) => (it.help_uri ? <a className="text-blue-600 underline" href={it.help_uri} target="_blank" rel="noreferrer">Docs</a> : <span className="text-slate-400">—</span>) },
              { key: 'exploit', header: 'Exploit', sortable: false, render: (it) => {
                const k = String(it.rule_id||'')
                const st = cqExploitMap[k]?.status ?? null
                const cls = st===true ? 'bg-green-600 text-white' : st===false ? 'bg-slate-300 text-slate-900' : 'bg-slate-100 text-slate-800'
                const label = st===true ? 'True' : st===false ? 'False' : 'Unknown'
                return (
                  <button type="button" className={`text-xs px-2 py-0.5 rounded border ${cls}`} onClick={() => openCqManage(k)} title="Manage exploit status">
                    {label}
                  </button>
                )
              } },
              { key: 'ask_ai', header: 'Ask AI', sortable: false, render: (it) => (
                <button type="button" className="text-xs px-2 py-0.5 border rounded" onClick={() => setCqAiCtx(it)}>Ask AI</button>
              ) },
            ]
            return (
              <>
                <DataTable
                  data={cqFindings}
                  columns={columns}
                  defaultPageSize={10}
                  filterKeys={['severity','rule_id','file','message']}
                />
                {cqManageKey && !fsOpen && (
                  <div className="mt-3 border rounded p-3 bg-white">
                    <div className="text-sm font-medium mb-2">Manage Exploit Status — {cqManageKey}</div>
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-sm mb-2">
                      <label className="flex items-center gap-2">
                        <input type="checkbox" checked={cqManageStatus} onChange={e=>setCqManageStatus(e.target.checked)} />
                        <span>Exploit available</span>
                      </label>
                      <div className="md:col-span-2">
                        <div className="text-xs text-slate-600 mb-1">Citations (one per line)</div>
                        <textarea className="border rounded px-2 py-1 w-full min-h-[80px]" value={cqManageCitations} onChange={e=>setCqManageCitations(e.target.value)} placeholder="https://exploit-db.com/...\nhttps://github.com/owner/repo" />
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      <button type="button" className="px-3 py-1 bg-blue-600 text-white rounded" onClick={saveCqManage}>Save</button>
                      <button type="button" className="px-3 py-1 bg-slate-200 rounded" onClick={()=>setCqManageKey(null)}>Cancel</button>
                    </div>
                  </div>
                )}
                {cqAiCtx && !fsOpen && (
                  <div className="mt-3">
                    <AiAssistantPanel
                      target="codeql"
                      projectId={item.uuid}
                      repoShort={(cqRepo || repoName || undefined)}
                      context={cqAiCtx}
                      onClose={() => setCqAiCtx(null)}
                    />
                  </div>
                )}
              </>
            )
          })()}
        </div>
        </div>

          {/* Close left column and add Section Nav */}
          </div>
          <div className="hidden lg:block h-fit sticky top-4">
            <div className="bg-white rounded shadow-sm border p-3">
              <div className="font-medium text-sm mb-2">Sections</div>
              <ul className="space-y-1 text-sm">
                <li className="flex items-center justify-between"><a href="#overview" className="text-blue-600 hover:underline">Overview</a></li>
                <li className="flex items-center justify-between"><a href="#languages" className="text-blue-600 hover:underline">Languages</a><span className="ml-2 inline-flex items-center justify-center min-w-[1.25rem] rounded-full bg-slate-100 text-slate-700 text-xs px-1">1</span></li>
                <li className="flex items-center justify-between"><a href="#repo" className="text-blue-600 hover:underline">Repo</a><span className="ml-2 inline-flex items-center justify-center min-w-[1.25rem] rounded-full bg-slate-100 text-slate-700 text-xs px-1">2</span></li>
                <li className="flex items-center justify-between"><a href="#build" className="text-blue-600 hover:underline">Build</a><span className="ml-2 inline-flex items-center justify-center min-w-[1.25rem] rounded-full bg-slate-100 text-slate-700 text-xs px-1">3</span></li>
                <li className="flex items-center justify-between"><a href="#findings" className="text-blue-600 hover:underline">Findings</a><span className="ml-2 inline-flex items-center justify-center min-w-[1.25rem] rounded-full bg-slate-100 text-slate-700 text-xs px-1">2</span></li>
                <li className="flex items-center justify-between"><a href="#vulnerabilities" className="text-blue-600 hover:underline">Vulnerabilities</a><span className="ml-2 inline-flex items-center justify-center min-w-[1.25rem] rounded-full bg-slate-100 text-slate-700 text-xs px-1">1</span></li>
              </ul>
            </div>
          </div>
        </div>
      </main>

      {/* Exploit Help Modal */}
      <ExploitHelpModal open={exploitHelpOpen} onClose={() => setExploitHelpOpen(false)} />

      {/* Ask AI Drawer */}
      <div className={`fixed top-0 right-0 h-full w-full sm:w-[28rem] bg-white shadow-2xl border-l z-50 transform transition-transform ${askAiOpen ? 'translate-x-0' : 'translate-x-full'}`}>
        <div className="flex items-center justify-between p-3 border-b">
          <div className="font-medium">Ask AI</div>
          <button className="px-2 py-1 border rounded" onClick={() => setAskAiOpen(false)}>Close</button>
        </div>
        <div className="p-3 space-y-3 text-sm">
          <label className="flex flex-col">
            <span className="text-xs text-slate-600">Question</span>
            <textarea className="border rounded px-2 py-1 min-h-[100px]" value={askAiQuestion} onChange={e=>setAskAiQuestion(e.target.value)} placeholder="Ask something about the visible tables..." />
          </label>
          <div className="flex items-center gap-2">
            <button className="px-3 py-1 bg-blue-600 text-white rounded disabled:opacity-50" disabled={askAiBusy || !askAiQuestion.trim()} onClick={onAskAiRun}>
              {askAiBusy ? 'Running…' : 'Run'}
            </button>
            <button className="px-3 py-1 bg-slate-200 rounded" onClick={() => setAskAiQuestion('')}>Clear</button>
          </div>
          <div className="text-xs text-slate-600">Response</div>
          <div className="border rounded p-2 bg-slate-50 whitespace-pre-wrap min-h-[120px]">{askAiResponse || '—'}</div>
          {(() => {
            try {
              const m = /```json\s*([\s\S]*?)\s*```/m.exec(askAiResponse || '')
              if (!m) return null
              const parsed = JSON.parse(m[1])
              const suggestions = Array.isArray(parsed?.suggestions) ? parsed.suggestions : []
              if (suggestions.length === 0) return null
              return (
                <div className="space-y-2">
                  <div className="text-xs text-slate-600">Suggestions</div>
                  <ul className="space-y-1">
                    {suggestions.map((s:any, idx:number) => (
                      <li key={idx} className="flex items-center justify-between gap-2">
                        <span className="text-xs">{s.tableId}.{s.field} → {String(s.value)}</span>
                        <button className="px-2 py-0.5 text-xs border rounded" onClick={() => {
                          if (fsOpen && fsConfig && fsConfig.id === s.tableId) {
                            const rows = [...fsConfig.rows]
                            if (Array.isArray(rows) && rows[s.rowIndex]) {
                              rows[s.rowIndex] = { ...rows[s.rowIndex], [s.field]: s.value }
                              setFsConfig({ ...fsConfig, rows })
                            }
                          }
                        }}>Apply suggestion</button>
                      </li>
                    ))}
                  </ul>
                </div>
              )
            } catch { return null }
          })()}
        </div>
      </div>

      {/* Floating Ask AI button */}
      <button
        type="button"
        className="fixed bottom-4 right-4 px-3 py-2 bg-amber-500 text-white rounded shadow-lg"
        onClick={() => setAskAiOpen(true)}
        title="Ask AI"
      >
        Ask AI
      </button>

      {/* Fullscreen overlay for tables */}
      {fsOpen && fsConfig && (
        <div className="fixed inset-0 z-50 bg-black/60">
          <div className="absolute inset-0 md:inset-6 bg-white rounded shadow-lg flex flex-col">
            <div className="flex items-center justify-between p-3 border-b">
              <div className="font-medium">{fsConfig.name}</div>
              <div className="flex items-center gap-2">
                <label className="text-xs flex items-center gap-1">
                  <span>Density</span>
                  <select className="border rounded px-2 py-1" value={fsDensity} onChange={e => setFsDensity(e.target.value as any)}>
                    <option value="comfortable">Comfortable</option>
                    <option value="compact">Compact</option>
                  </select>
                </label>
                <button className="px-2 py-1 border rounded" onClick={() => downloadCsv(fsConfig.id, serializeCsvFromFields(fsEffectiveFields, fsConfig.rows))}>Export CSV</button>
                <button className="px-2 py-1 border rounded" onClick={() => setFsOpen(false)}>Close</button>
              </div>
            </div>
            <div className={`${fsDensity === 'compact' ? 'text-xs' : 'text-sm'} flex-1 overflow-auto`}>
              <div className="p-3">
                <DataTable
                  data={fsConfig.rows}
                  columns={(fsConfig.columns && fsConfig.columns.length > 0)
                    ? overlayColumns
                    : fsEffectiveFields.map(f => ({ key: f.key, header: f.label, sortable: true, filter: { type: 'text' } }))}
                  defaultPageSize={10}
                  filterKeys={(fsConfig.columns && fsConfig.columns.length > 0)
                    ? overlayColumns.map(c => String(c.key))
                    : fsEffectiveFields.map(f => f.key)}
                />
                {fsConfig.id === 'contributors' && item ? (
                  <div className="mt-3 grid grid-cols-1 md:grid-cols-2 gap-4">
                    <ChartHost
                      datasetKey={`fs.contributors.top.${item.uuid}`}
                      title="Top Contributors"
                      adapter={ProjectContributorsAdapter}
                      defaultType="bar"
                      availableTypes={["bar","donut","line"]}
                      params={{ projectId: item.uuid }}
                    />
                    <ChartHost
                      datasetKey={`fs.contributors.trend.${item.uuid}`}
                      title="Contributors Trend"
                      adapter={ProjectCommitsActivityAdapter}
                      defaultType="line"
                      availableTypes={["line","bar"]}
                      params={{ projectId: item.uuid }}
                    />
                  </div>
                ) : null}
                {fsConfig.id === 'commits' && item ? (
                  <div className="mt-3">
                    <ChartHost
                      datasetKey={`fs.commits.trend.${item.uuid}`}
                      title="Commits Activity"
                      adapter={ProjectCommitsActivityAdapter}
                      defaultType="line"
                      availableTypes={["line","bar"]}
                      params={{ projectId: item.uuid }}
                    />
                  </div>
                ) : null}
                {fsManageKey && (
                  <div className="mt-3 border rounded p-3 bg-white">
                    <div className="text-sm font-medium mb-2">Manage Exploit Status — {fsManageKey}</div>
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-sm mb-2">
                      <label className="flex items-center gap-2">
                        <input type="checkbox" checked={fsManageStatus} onChange={e=>setFsManageStatus(e.target.checked)} />
                        <span>Exploit available</span>
                      </label>
                      <div className="md:col-span-2">
                        <div className="text-xs text-slate-600 mb-1">Citations (one per line)</div>
                        <textarea className="border rounded px-2 py-1 w-full min-h-[80px]" value={fsManageCitations} onChange={e=>setFsManageCitations(e.target.value)} placeholder="https://exploit-db.com/...\nhttps://github.com/owner/repo" />
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      <button type="button" className="px-3 py-1 bg-blue-600 text-white rounded" onClick={saveFsManage}>Save</button>
                      <button type="button" className="px-3 py-1 bg-slate-200 rounded" onClick={()=>setFsManageKey(null)}>Cancel</button>
                    </div>
                  </div>
                )}
                {fsAiCtx && (
                  <div className="mt-3">
                    <AiAssistantPanel
                      target={fsConfig.id === 'codeql' ? 'codeql' : fsConfig.id === 'cicd' ? 'cicd' : fsConfig.id === 'secrets' ? 'secret' : fsConfig.id === 'contributors' ? 'cicd' : fsConfig.id === 'commits' ? 'cicd' : fsConfig.id === 'terraform' ? 'terraform' : fsConfig.id === 'oss' ? 'oss' : 'cicd'}
                      projectId={item.uuid}
                      repoShort={repoName || undefined}
                      context={fsAiCtx}
                      onClose={() => setFsAiCtx(null)}
                    />
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
