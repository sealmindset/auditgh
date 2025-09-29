import React, { useEffect, useMemo, useState } from 'react'
import DataTable, { ColumnDef } from './DataTable'
import { xhrGetJson, xhrPostJson } from '../lib/xhr'
import AiAssistantPanel from './AiAssistantPanel'

// Cache parsed results by absolute path to avoid repeated fetch/parse
const tfCache = new Map<string, any[]>()

export default function TerraformFindings({ projectId, repoName, onRequestFullscreen, overlayActive = false }: { projectId: string; repoName: string | null; onRequestFullscreen?: (cfg: { id: string; name: string; fields?: Array<{key:string;label:string}>; columns?: ColumnDef<any>[]; rows: any[] }) => void, overlayActive?: boolean }) {
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [rows, setRows] = useState<any[]>([])
  const [aiCtx, setAiCtx] = useState<any | null>(null)
  const [exploitMap, setExploitMap] = useState<Record<string, { status: boolean | null; evidence: any[] }>>({})
  const [manageKey, setManageKey] = useState<string | null>(null)
  const [manageStatus, setManageStatus] = useState<boolean>(false)
  const [manageCitations, setManageCitations] = useState<string>('')

  const checkovPath = useMemo(() => (repoName ? `/terraform_reports/${repoName}/${repoName}_checkov.json` : null), [repoName])
  const trivyPath = useMemo(() => (repoName ? `/terraform_reports/${repoName}/${repoName}_trivy_fs.json` : null), [repoName])

  useEffect(() => {
    if (!projectId) return
    let canceled = false
    async function load() {
      setLoading(true)
      setError(null)
      try {
        let r: any[] | null = null
        // 1) Prefer DB via PostgREST
        const dbKey = `db:${projectId}:${repoName || ''}`
        const cachedDb = tfCache.get(dbKey)
        if (cachedDb) {
          r = cachedDb
        } else {
          try {
            const sel = 'project_id,repo_short,scanner,rule_id,rule_name,severity,resource,file_path,line_start,guideline_url,created_at'
            let url = `/db/terraform_findings?select=${encodeURIComponent(sel)}&project_id=eq.${encodeURIComponent(projectId)}&order=created_at.desc&limit=200`
            if (repoName) url += `&repo_short=eq.${encodeURIComponent(repoName)}`
            const rows = await xhrGetJson(url)
            const parsed = Array.isArray(rows) ? rows.map(dbRowToUi) : []
            if (parsed.length > 0) {
              tfCache.set(dbKey, parsed)
              r = parsed
            }
          } catch {
            // ignore DB errors; try static fallback
          }
        }
        // 2) Fallback to static files if DB empty or missing
        if (checkovPath) {
          const cached = tfCache.get(`checkov:${checkovPath}`)
          if (cached) r = cached
          else {
            try {
              const json = await xhrGetJson(checkovPath)
              const parsed = parseCheckov(json)
              tfCache.set(`checkov:${checkovPath}`, parsed)
              r = parsed
            } catch (e) {
              // ignore; likely 404 or parse error
            }
          }
        }
        if ((!r || r.length === 0) && trivyPath) {
          const cached = tfCache.get(`trivy:${trivyPath}`)
          if (cached) r = cached
          else {
            try {
              const json = await xhrGetJson(trivyPath)
              const parsed = parseTrivy(json)
              tfCache.set(`trivy:${trivyPath}`, parsed)
              r = parsed
            } catch (e) {
              // ignore as well
            }
          }
        }
        if (!canceled) setRows(r || [])
      } catch (e: any) {
        if (!canceled) setError(e?.message || 'Failed to load Terraform report')
      } finally {
        if (!canceled) setLoading(false)
      }
    }
    // eslint-disable-next-line @typescript-eslint/no-floating-promises
    load()
    return () => { canceled = true }
  }, [projectId, repoName, checkovPath, trivyPath])

  // Fetch exploit statuses for visible Terraform rule IDs
  useEffect(() => {
    async function run() {
      try {
        const ids = Array.from(new Set((rows||[]).map((r:any) => String(r.rule_id||'').trim()).filter(Boolean)))
        if (!ids.length) { setExploitMap({}); return }
        const url = `/api/exploitability?type=terraform_rule&keys=${encodeURIComponent(ids.join(','))}`
        const data = await xhrGetJson(url)
        const out: Record<string, { status: boolean | null; evidence: any[] }> = {}
        for (const it of (data?.items||[])) out[String(it.key)] = { status: it.exploit_available===true ? true : (it.exploit_available===false ? false : null), evidence: it.evidence||[] }
        setExploitMap(out)
      } catch {
        // ignore
      }
    }
    // eslint-disable-next-line @typescript-eslint/no-floating-promises
    run()
  }, [rows])

  function openManage(ruleId: string) {
    const key = String(ruleId||'')
    setManageKey(key)
    const st = exploitMap[key]?.status ?? null
    setManageStatus(st === true)
    const ev = exploitMap[key]?.evidence || []
    setManageCitations((ev||[]).map((e:any)=>String(e.url||'')).filter(Boolean).join('\n'))
  }

  async function saveManage() {
    if (!manageKey) return
    const urls = manageCitations.split(/\s+/).map((s: string)=>s.trim()).filter(Boolean)
    if (manageStatus && urls.length===0) return
    try {
      const evidence = urls.map((u: string) => ({ url: u }))
      await xhrPostJson(`/api/exploitability`, { type: 'terraform_rule', key: manageKey, exploit_available: !!manageStatus, evidence })
      const data = await xhrGetJson(`/api/exploitability?type=terraform_rule&key=${encodeURIComponent(manageKey)}`)
      const it = (data?.items||[])[0]
      if (it) setExploitMap((prev) => ({ ...prev, [String(it.key)]: { status: it.exploit_available===true ? true : (it.exploit_available===false ? false : null), evidence: it.evidence||[] } }))
      setManageKey(null)
    } catch {
      // ignore
    }
  }

  // Severity chips filter (clickable) — mirrors OSS section behavior
  const [sevFilter, setSevFilter] = useState<Record<'Critical'|'High'|'Medium'|'Low'|'Unknown', boolean>>({
    Critical: true,
    High: true,
    Medium: true,
    Low: true,
    Unknown: true,
  })
  function toggleSev(sev: keyof typeof sevFilter) {
    setSevFilter((prev) => ({ ...prev, [sev]: !prev[sev] }))
  }
  function setAll(on: boolean) {
    setSevFilter({ Critical: on, High: on, Medium: on, Low: on, Unknown: on })
  }

function dbRowToUi(r: any): any {
  return {
    tool: (r?.scanner || '').toString().toLowerCase(),
    rule_id: r?.rule_id || '',
    rule_name: r?.rule_name || '',
    severity: r?.severity || 'unknown',
    resource: r?.resource || '',
    file_path: r?.file_path || '',
    line_start: typeof r?.line_start === 'number' ? r.line_start : undefined,
    guideline_url: r?.guideline_url || null,
    repo_short: r?.repo_short || '',
    project_id: r?.project_id || '',
    created_at: r?.created_at || null,
  }
}

  // Totals for severity chips (display-only)
  const totals = useMemo(() => {
    const t: Record<'Critical'|'High'|'Medium'|'Low'|'Unknown', number> = { Critical: 0, High: 0, Medium: 0, Low: 0, Unknown: 0 }
    for (const r of rows || []) t[normSeverity(r?.severity)]++
    return t
  }, [rows])

  // External enum filter for DataTable: keep in lockstep with chips
  const allSev = ['Critical','High','Medium','Low','Unknown'] as const
  const externalEnumFilters = useMemo(() => {
    const selected = allSev.filter((s) => sevFilter[s])
    return { severity: selected.length === allSev.length ? undefined : selected }
  }, [sevFilter])
  const handleExternalEnumFiltersChange = (next: Record<string, string[] | undefined>) => {
    const sel = next['severity']
    if (sel === undefined) {
      // Full selection
      setSevFilter({ Critical: true, High: true, Medium: true, Low: true, Unknown: true })
    } else {
      setSevFilter({
        Critical: sel.includes('Critical'),
        High: sel.includes('High'),
        Medium: sel.includes('Medium'),
        Low: sel.includes('Low'),
        Unknown: sel.includes('Unknown'),
      })
    }
  }

  const columns: ColumnDef<any>[] = [
    { key: 'rule_id', header: 'Rule ID', sortable: true, filter: { type: 'text', getValue: (r) => String(r.rule_id || '') } },
    { key: 'rule_name', header: 'Rule Name', sortable: true, filter: { type: 'text', getValue: (r) => String(r.rule_name || '') } },
    { key: 'severity', header: 'Severity', sortable: true, filter: { type: 'enum', enumValues: ['Critical','High','Medium','Low','Unknown'], getValue: (r) => normSeverity(r.severity) }, render: (r) => (<SeverityBadge severity={r.severity} />) },
    { key: 'resource', header: 'Resource', sortable: true, filter: { type: 'text', getValue: (r) => String(r.resource || '') } },
    { key: 'file_path', header: 'File', sortable: true, filter: { type: 'text', getValue: (r) => String(r.file_path || '') }, render: (r) => (
      <span title={r.file_path || ''}>{r.file_path}{typeof r.line_start === 'number' ? `:${r.line_start}` : ''}</span>
    ) },
    { key: 'tool', header: 'Tool', sortable: true, filter: { type: 'enum', enumValues: ['checkov','trivy'] } },
    { key: 'guideline_url', header: 'Guideline', sortable: false, render: (r) => r.guideline_url ? <a href={r.guideline_url} target="_blank" rel="noreferrer" className="text-blue-600 hover:underline">Link</a> : <span className="text-slate-400">—</span> },
    { key: 'exploit', header: 'Exploit', sortable: false, render: (r) => {
      const k = String(r.rule_id||'')
      const st = exploitMap[k]?.status ?? null
      const cls = st===true ? 'bg-green-600 text-white' : st===false ? 'bg-slate-300 text-slate-900' : 'bg-slate-100 text-slate-800'
      const label = st===true ? 'True' : st===false ? 'False' : 'Unknown'
      return (
        <button type="button" className={`text-xs px-2 py-0.5 rounded border ${cls}`} onClick={() => openManage(k)} title="Manage exploit status">
          {label}
        </button>
      )
    } },
    { key: 'ask_ai', header: 'Ask AI', sortable: false, render: (r) => (
      <button type="button" className="text-xs px-2 py-0.5 border rounded" onClick={() => setAiCtx(r)}>Ask AI</button>
    ) },
  ]

  return (
    <div className="bg-white p-4 rounded shadow-sm">
      <div className="flex items-center justify-between mb-2">
        <h2 className="font-medium">Terraform Findings</h2>
        <div className="text-xs text-slate-600 flex items-center gap-2">
          <span>Checkov / Trivy</span>
          <button
            type="button"
            className="px-2 py-1 border rounded bg-slate-100 hover:bg-slate-200"
            onClick={() => onRequestFullscreen && onRequestFullscreen({
              id: 'terraform',
              name: 'Terraform Findings',
              columns,
              rows,
            })}
          >
            Fullscreen
          </button>
        </div>
      </div>
      {(rows || []).length > 0 && (
        <div className="flex flex-wrap gap-2 items-center text-sm mb-2">
          <span className="mr-1">Severity:</span>
          {(['Critical','High','Medium','Low','Unknown'] as const).map((s) => (
            <button
              key={s}
              className={`px-2 py-0.5 rounded border ${sevFilter[s] ? 'bg-slate-200 border-slate-300 text-slate-900' : 'bg-white border-slate-200 text-slate-500'}`}
              onClick={() => toggleSev(s)}
              type="button"
            >
              {s}
            </button>
          ))}
          <span className="mx-1">|</span>
          <button className="px-2 py-0.5 rounded border bg-white border-slate-200 text-slate-600" onClick={() => setAll(true)} type="button">All</button>
          <button className="px-2 py-0.5 rounded border bg-white border-slate-200 text-slate-600" onClick={() => setAll(false)} type="button">None</button>
        </div>
      )}
      {(rows || []).length > 0 && (
        <div className="flex flex-wrap gap-2 items-center text-sm mb-2">
          <span className="mr-1">Totals:</span>
          {(['Critical','High','Medium','Low','Unknown'] as const).map((s) => (
            <span key={s} className={`px-2 py-0.5 rounded text-white ${severityBgClass(s)}`}>{s}: {totals[s] ?? 0}</span>
          ))}
        </div>
      )}
      {!repoName ? (
        <div className="text-sm text-slate-600">No repository URL set for this project.</div>
      ) : loading ? (
        <div className="text-sm text-slate-600">Loading…</div>
      ) : error ? (
        <div className="text-sm text-red-700">{error}</div>
      ) : (rows || []).length === 0 ? (
        <div className="text-sm text-slate-600">No Terraform findings found.</div>
      ) : (
        <>
          <DataTable
            data={rows}
            columns={columns}
            defaultPageSize={10}
            pageSizeOptions={[10,25,50]}
            filterKeys={['rule_id','rule_name','severity','resource','file_path','tool']}
            searchPlaceholder="Search Terraform findings…"
            externalEnumFilters={externalEnumFilters}
            onExternalEnumFiltersChange={handleExternalEnumFiltersChange}
          />
          {manageKey && !overlayActive && (
            <div className="mt-3 border rounded p-3 bg-white">
              <div className="text-sm font-medium mb-2">Manage Exploit Status — {manageKey}</div>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-sm mb-2">
                <label className="flex items-center gap-2">
                  <input type="checkbox" checked={manageStatus} onChange={e=>setManageStatus(e.target.checked)} />
                  <span>Exploit available</span>
                </label>
                <div className="md:col-span-2">
                  <div className="text-xs text-slate-600 mb-1">Citations (one per line)</div>
                  <textarea className="border rounded px-2 py-1 w-full min-h-[80px]" value={manageCitations} onChange={e=>setManageCitations(e.target.value)} placeholder="https://exploit-db.com/...\nhttps://github.com/owner/repo" />
                </div>
              </div>
              <div className="flex items-center gap-2">
                <button type="button" className="px-3 py-1 bg-blue-600 text-white rounded" onClick={saveManage}>Save</button>
                <button type="button" className="px-3 py-1 bg-slate-200 rounded" onClick={()=>setManageKey(null)}>Cancel</button>
              </div>
            </div>
          )}
          {aiCtx && !overlayActive && (
            <div className="mt-3">
              <AiAssistantPanel
                target="terraform"
                projectId={projectId}
                repoShort={repoName || undefined}
                context={aiCtx}
                onClose={() => setAiCtx(null)}
              />
            </div>
          )}
        </>
      )}
      </div>
  )
}

function parseCheckov(json: any): any[] {
  try {
    const failed = (json?.results?.failed_checks || []) as any[]
    return failed.map((r) => ({
      tool: 'checkov',
      rule_id: r?.check_id || '',
      rule_name: r?.check_name || '',
      severity: r?.severity || 'Unknown',
      resource: r?.resource || '',
      file_path: r?.repo_file_path || r?.file_path || r?.file_abs_path || '',
      line_start: Array.isArray(r?.file_line_range) ? r.file_line_range[0] : undefined,
      evaluated_keys: Array.isArray(r?.check_result?.evaluated_keys) ? r.check_result.evaluated_keys.join(', ') : '',
      guideline_url: r?.guideline || null,
    }))
  } catch {
    return []
  }
}

function parseTrivy(json: any): any[] {
  try {
    const results = (json?.Results || []) as any[]
    const out: any[] = []
    for (const res of results) {
      const target = res?.Target || ''
      const mis = (res?.Misconfigurations || []) as any[]
      for (const m of mis) {
        out.push({
          tool: 'trivy',
          rule_id: m?.ID || '',
          rule_name: m?.Title || '',
          severity: m?.Severity || 'Unknown',
          resource: m?.CauseMetadata?.Resource || '',
          file_path: target || '',
          line_start: typeof m?.CauseMetadata?.StartLine === 'number' ? m.CauseMetadata.StartLine : undefined,
          evaluated_keys: '',
          guideline_url: m?.PrimaryURL || (Array.isArray(m?.References) && m.References.length > 0 ? m.References[0] : null),
        })
      }
    }
    return out
  } catch {
    return []
  }
}

function normSeverity(s: any): 'Critical'|'High'|'Medium'|'Low'|'Unknown' {
  const v = String(s || '').trim().toLowerCase()
  if (v.startsWith('crit')) return 'Critical'
  if (v.startsWith('hi')) return 'High'
  if (v.startsWith('med')) return 'Medium'
  if (v.startsWith('lo')) return 'Low'
  return 'Unknown'
}

function severityBgClass(sev: any): string {
  switch (normSeverity(sev)) {
    case 'Critical': return 'bg-red-600'
    case 'High': return 'bg-orange-500'
    case 'Medium': return 'bg-amber-500'
    case 'Low': return 'bg-slate-500'
    default: return 'bg-slate-400'
  }
}

const SeverityBadge: React.FC<{ severity: any }> = ({ severity }) => {
  const label = normSeverity(severity)
  return <span className={`px-2 py-0.5 rounded text-white text-xs ${severityBgClass(label)}`}>{label}</span>
}
