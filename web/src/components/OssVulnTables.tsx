import React, { useEffect, useMemo, useState } from 'react'
import DataTable, { ColumnDef } from './DataTable'
import { xhrGetJson, xhrGetText, xhrPostJson } from '../lib/xhr'
import AiAssistantPanel from './AiAssistantPanel'

// Simple in-memory cache to avoid re-fetching/parsing when navigating
const reportCache = new Map<string, { summary: any[]; multiple: any[]; vulns: any[] }>()

export default function OssVulnTables({ repoName, projectId, onRequestFullscreen, overlayActive = false }: { repoName: string | null, projectId?: string, onRequestFullscreen?: (cfg: { id: string; name: string; fields?: Array<{key:string;label:string}>; columns?: ColumnDef<any>[]; rows: any[] }) => void, overlayActive?: boolean }) {
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [summaryRows, setSummaryRows] = useState<any[]>([])
  const [multipleRows, setMultipleRows] = useState<any[]>([])
  const [vulnRows, setVulnRows] = useState<any[]>([])
  const [aiCtx, setAiCtx] = useState<any | null>(null)
  const [exploitMap, setExploitMap] = useState<Record<string, { status: boolean | null; evidence: any[] }>>({})
  const [manageKey, setManageKey] = useState<{ type: 'cve'|'ghsa'; key: string } | null>(null)
  const [manageStatus, setManageStatus] = useState<boolean>(false)
  const [manageCitations, setManageCitations] = useState<string>('')

  // Per-session collapse state (default collapsed) for Multiple and Vulnerabilities sections
  const collapsedMultipleKey = useMemo(() => `oss.multiple.collapsed:${repoName || ''}`, [repoName])
  const collapsedVulnsKey = useMemo(() => `oss.vulns.collapsed:${repoName || ''}`, [repoName])

  function getSessionBool(key: string, fallback: boolean): boolean {
    try {
      const v = sessionStorage.getItem(key)
      if (v === null) return fallback
      return v === 'true'
    } catch {
      return fallback
    }
  }

  const [collapsedMultiple, setCollapsedMultiple] = useState<boolean>(() => getSessionBool(collapsedMultipleKey, true))
  const [collapsedVulns, setCollapsedVulns] = useState<boolean>(() => getSessionBool(collapsedVulnsKey, true))

  // Update state when repo changes (key changes)
  useEffect(() => { setCollapsedMultiple(getSessionBool(collapsedMultipleKey, true)) }, [collapsedMultipleKey])
  useEffect(() => { setCollapsedVulns(getSessionBool(collapsedVulnsKey, true)) }, [collapsedVulnsKey])

  // Persist on change
  useEffect(() => { try { sessionStorage.setItem(collapsedMultipleKey, collapsedMultiple ? 'true' : 'false') } catch {} }, [collapsedMultipleKey, collapsedMultiple])
  useEffect(() => { try { sessionStorage.setItem(collapsedVulnsKey, collapsedVulns ? 'true' : 'false') } catch {} }, [collapsedVulnsKey, collapsedVulns])

  const reportPath = useMemo(() => {
    if (!repoName) return null
    return `/oss_reports/${repoName}/${repoName}_oss.md`
  }, [repoName])

  useEffect(() => {
    if (!reportPath) return
    setLoading(true)
    setError(null)
    const cached = reportCache.get(reportPath)
    if (cached) {
      setSummaryRows(cached.summary)
      setMultipleRows(cached.multiple)
      setVulnRows(cached.vulns)
      setLoading(false)
      return
    }
    xhrGetText(reportPath)
      .then((text) => {
        const parsed = parseReport(text)
        reportCache.set(reportPath, parsed)
        setSummaryRows(parsed.summary)
        setMultipleRows(parsed.multiple)
        setVulnRows(parsed.vulns)
      })
      .catch((e: any) => setError(e?.message || 'Failed to load OSS report'))
      .finally(() => setLoading(false))
  }, [reportPath])

  // Fetch exploit statuses for visible CVE/GHSA vulnerabilities
  useEffect(() => {
    async function fetchStatuses() {
      try {
        const ids = Array.from(new Set((vulnRows||[]).map(r => String(r.vuln_id||'').toUpperCase()).filter(Boolean)))
        const cves = ids.filter(s => /^CVE-\d{4}-\d{4,}$/.test(s))
        const ghsas = ids.filter(s => /^GHSA-/.test(s))
        const out: Record<string, { status: boolean | null; evidence: any[] }> = {}
        if (cves.length) {
          const data = await xhrGetJson(`/api/exploitability?type=cve&keys=${encodeURIComponent(cves.join(','))}`)
          for (const it of (data?.items||[])) out[String(it.key).toUpperCase()] = { status: it.exploit_available===true ? true : (it.exploit_available===false ? false : null), evidence: it.evidence||[] }
        }
        if (ghsas.length) {
          const data2 = await xhrGetJson(`/api/exploitability?type=ghsa&keys=${encodeURIComponent(ghsas.join(','))}`)
          for (const it of (data2?.items||[])) out[String(it.key).toUpperCase()] = { status: it.exploit_available===true ? true : (it.exploit_available===false ? false : null), evidence: it.evidence||[] }
        }
        setExploitMap(prev => ({ ...prev, ...out }))
      } catch {
        // ignore lookup errors
      }
    }
    if ((vulnRows||[]).length) {
      // eslint-disable-next-line @typescript-eslint/no-floating-promises
      fetchStatuses()
    }
  }, [vulnRows])

  async function openManage(keyRaw: string) {
    const key = String(keyRaw||'').toUpperCase()
    const type: 'cve'|'ghsa' = /^CVE-\d{4}-\d{4,}$/.test(key) ? 'cve' : 'ghsa'
    setManageKey({ type, key })
    const st = exploitMap[key]?.status ?? null
    setManageStatus(st === true)
    const ev = exploitMap[key]?.evidence || []
    setManageCitations((ev||[]).map((e:any)=>String(e.url||'')).filter(Boolean).join('\n'))
  }

  async function saveManage() {
    if (!manageKey) return
    const urls = manageCitations.split(/\s+/).map(s=>s.trim()).filter(Boolean)
    if (manageStatus && urls.length===0) return
    try {
      const evidence = urls.map(u => ({ url: u }))
      await xhrPostJson('/api/exploitability', { type: manageKey.type, key: manageKey.key, exploit_available: !!manageStatus, evidence })
      const data = await xhrGetJson(`/api/exploitability?type=${encodeURIComponent(manageKey.type)}&key=${encodeURIComponent(manageKey.key)}`)
      const it = (data?.items||[])[0]
      if (it) setExploitMap(prev => ({ ...prev, [String(it.key).toUpperCase()]: { status: it.exploit_available===true ? true : (it.exploit_available===false ? false : null), evidence: it.evidence||[] } }))
      setManageKey(null)
    } catch {
      // ignore save errors
    }
  }

  // Use per-column filters within DataTable; no global severity chips/totals
  const filteredSummary = useMemo(() => summaryRows || [], [summaryRows])
  const filteredMultiple = useMemo(() => multipleRows || [], [multipleRows])
  const filteredVulns = useMemo(() => vulnRows || [], [vulnRows])

  const columnsSummary: ColumnDef<any>[] = [
    { key: 'package', header: 'Package', filter: { type: 'text', getValue: (r) => String(r.package || '') } },
    { key: 'version', header: 'Version', filter: { type: 'text', getValue: (r) => String(r.version || '') } },
    { key: 'count', header: 'Count' },
    {
      key: 'max_severity',
      header: 'Max Severity',
      filter: { type: 'enum', enumValues: ['Critical','High','Medium','Low','Unknown'], getValue: (r) => normSeverity(r.max_severity) },
      render: (row) => <SeverityBadge severity={row.max_severity} />,
    },
    { key: 'description', header: 'Description', sortable: false, filter: { type: 'text', getValue: (r) => String(r.description || '') } },
    { key: 'fixed_version', header: 'Fixed Version', filter: { type: 'text', getValue: (r) => String(r.fixed_version || '') } },
    { key: 'mitigation', header: 'Mitigation', sortable: false, filter: { type: 'text', getValue: (r) => String(r.mitigation || '') } },
  ]

  const columnsMultiple: ColumnDef<any>[] = [
    { key: 'package', header: 'Package', filter: { type: 'text', getValue: (r) => String(r.package || '') } },
    { key: 'version', header: 'Version', filter: { type: 'text', getValue: (r) => String(r.version || '') } },
    { key: 'count', header: 'Count' },
    {
      key: 'max_severity',
      header: 'Max Severity',
      filter: { type: 'enum', enumValues: ['Critical','High','Medium','Low','Unknown'], getValue: (r) => normSeverity(r.max_severity) },
      render: (row) => <SeverityBadge severity={row.max_severity} />,
    },
    { key: 'description', header: 'Description', sortable: false, filter: { type: 'text', getValue: (r) => String(r.description || '') } },
    { key: 'fixed_version', header: 'Fixed Version', filter: { type: 'text', getValue: (r) => String(r.fixed_version || '') } },
    { key: 'mitigation', header: 'Mitigation', sortable: false, filter: { type: 'text', getValue: (r) => String(r.mitigation || '') } },
  ]

  const columnsVulns: ColumnDef<any>[] = [
    { key: 'package', header: 'Package', filter: { type: 'text', getValue: (r) => String(r.package || '') } },
    { key: 'version', header: 'Version', filter: { type: 'text', getValue: (r) => String(r.version || '') } },
    {
      key: 'vuln_id',
      header: 'Vulnerability ID',
      filter: { type: 'text', getValue: (r) => String(r.vuln_id || '') },
      render: (row) => {
        const id: string = row.vuln_id || ''
        const href = linkForVulnId(id)
        return href ? (
          <a href={href} target="_blank" rel="noreferrer" className="text-blue-600 hover:underline">{id}</a>
        ) : (id || '—')
      },
    },
    { key: 'severity', header: 'Severity', filter: { type: 'enum', enumValues: ['Critical','High','Medium','Low','Unknown'], getValue: (r) => normSeverity(r.severity) }, render: (row) => <SeverityBadge severity={row.severity} /> },
    { key: 'epss', header: 'EPSS Score' },
    { key: 'description', header: 'Description', sortable: false, filter: { type: 'text', getValue: (r) => String(r.description || '') } },
    { key: 'exploit', header: 'Exploit', sortable: false, render: (row) => {
      const k = String(row.vuln_id||'').toUpperCase()
      const st = exploitMap[k]?.status ?? null
      const cls = st===true ? 'bg-green-600 text-white' : st===false ? 'bg-slate-300 text-slate-900' : 'bg-slate-100 text-slate-800'
      const label = st===true ? 'True' : st===false ? 'False' : 'Unknown'
      return (
        <button type="button" className={`text-xs px-2 py-0.5 rounded border ${cls}`} onClick={() => openManage(k)} title="Manage exploit status">
          {label}
        </button>
      )
    } },
    { key: 'fixed_version', header: 'Fixed Version', filter: { type: 'text', getValue: (r) => String(r.fixed_version || '') } },
    { key: 'mitigation', header: 'Mitigation', sortable: false, filter: { type: 'text', getValue: (r) => String(r.mitigation || '') } },
    { key: 'ask_ai', header: 'Ask AI', sortable: false, render: (row) => (
      <button type="button" className="text-xs px-2 py-0.5 border rounded" onClick={() => setAiCtx(row)}>Ask AI</button>
    ) },
  ]

  return (
    <div className="bg-white p-4 rounded shadow-sm">
      <h2 className="font-medium mb-2">OSS Vulnerabilities</h2>
      {!repoName ? (
        <div className="text-sm text-slate-600">No repository URL set for this project.</div>
      ) : loading ? (
        <div className="text-sm text-slate-600">Loading…</div>
      ) : error ? (
        <div className="text-sm text-red-700">{error}</div>
      ) : (
        <div className="space-y-6">
          {/* Summary — always visible, no fullscreen */}
          <section className="bg-white p-3 rounded border">
            <h3 className="font-medium mb-2">Summary</h3>
            {summaryRows.length === 0 ? (
              <div className="text-sm text-slate-600">No summary found.</div>
            ) : (
              <DataTable
                data={filteredSummary}
                columns={columnsSummary}
                pageSizeOptions={[10, 25, 50]}
                defaultPageSize={10}
                filterKeys={['package', 'version', 'max_severity', 'description', 'fixed_version', 'mitigation', 'count']}
                searchPlaceholder="Search summary…"
              />
            )}
          </section>

          {/* Multiple Vulnerabilities — header + rows + optional Fullscreen */}
          <section className="bg-white p-3 rounded border">
            <div className="flex items-center justify-between mb-2">
              <h3 className="font-medium">Multiple Vulnerabilities</h3>
              <div className="text-xs text-slate-600 flex items-center gap-2">
                <button
                  type="button"
                  className="px-2 py-1 border rounded bg-white hover:bg-slate-50"
                  aria-expanded={!collapsedMultiple}
                  onClick={() => setCollapsedMultiple(!collapsedMultiple)}
                >
                  {collapsedMultiple ? 'Expand' : 'Collapse'}
                </button>
                <span>{multipleRows?.length || 0} rows</span>
                {onRequestFullscreen ? (
                  <button
                    type="button"
                    className="px-2 py-1 border rounded bg-slate-100 hover:bg-slate-200"
                    onClick={() => onRequestFullscreen({ id: 'oss_multiple', name: 'OSS — Multiple Vulnerabilities', columns: columnsMultiple, rows: multipleRows })}
                  >
                    Fullscreen
                  </button>
                ) : null}
              </div>
            </div>
            {collapsedMultiple ? null : (
              multipleRows.length === 0 ? (
                <div className="text-sm text-slate-600">No packages with multiple vulnerabilities.</div>
              ) : (
                <DataTable
                  data={filteredMultiple}
                  columns={columnsMultiple}
                  pageSizeOptions={[10, 25, 50]}
                  defaultPageSize={10}
                  filterKeys={['package', 'version', 'max_severity', 'description', 'fixed_version', 'mitigation', 'count']}
                  searchPlaceholder="Search multiple…"
                />
              )
            )}
          </section>

          {/* Vulnerabilities Found — header + rows + optional Fullscreen */}
          <section className="bg-white p-3 rounded border">
            <div className="flex items-center justify-between mb-2">
              <h3 className="font-medium">Vulnerabilities Found</h3>
              <div className="text-xs text-slate-600 flex items-center gap-2">
                <button
                  type="button"
                  className="px-2 py-1 border rounded bg-white hover:bg-slate-50"
                  aria-expanded={!collapsedVulns}
                  onClick={() => setCollapsedVulns(!collapsedVulns)}
                >
                  {collapsedVulns ? 'Expand' : 'Collapse'}
                </button>
                <span>{vulnRows?.length || 0} rows</span>
                {onRequestFullscreen ? (
                  <button
                    type="button"
                    className="px-2 py-1 border rounded bg-slate-100 hover:bg-slate-200"
                    onClick={() => onRequestFullscreen({ id: 'oss', name: 'OSS Vulnerabilities', columns: columnsVulns, rows: vulnRows })}
                  >
                    Fullscreen
                  </button>
                ) : null}
              </div>
            </div>
            {collapsedVulns ? null : (
              vulnRows.length === 0 ? (
                <div className="text-sm text-slate-600">No vulnerabilities found.</div>
              ) : (
                <>
                  <DataTable
                    data={filteredVulns}
                    columns={columnsVulns}
                    pageSizeOptions={[10, 25, 50]}
                    defaultPageSize={10}
                    filterKeys={['package', 'version', 'vuln_id', 'severity', 'epss', 'description', 'fixed_version', 'mitigation']}
                    searchPlaceholder="Search vulnerabilities…"
                  />
                  {manageKey && !overlayActive && (
                    <div className="mt-3 border rounded p-3 bg-white">
                      <div className="text-sm font-medium mb-2">Manage Exploit Status — {manageKey.key}</div>
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
                        target="oss"
                        projectId={projectId}
                        repoShort={repoName || undefined}
                        context={aiCtx}
                        onClose={() => setAiCtx(null)}
                      />
                    </div>
                  )}
                </>
              )
            )}
          </section>
        </div>
      )}
    </div>
  )
}

function parseReport(md: string): { summary: any[]; multiple: any[]; vulns: any[] } {
  // Try both possible headings for summary, prefer 'Package Summary (All Packages)'
  const summary = parseTableSection(md, /##\s*Package Summary \(All Packages\)/i) ||
                  parseTableSection(md, /##\s*Summary/i) || []
  const multiple = parseTableSection(md, /##\s*Packages with Multiple Vulnerabilities/i) || []
  const vulns = parseTableSection(md, /##\s*Vulnerabilities Found/i) || []

  // Normalize keys for DataTable
  const normSummary = summary.map((r) => ({
    package: r['Package'] ?? r['package'],
    version: r['Version'] ?? r['version'],
    count: numOrNull(r['Count'] ?? r['count']),
    max_severity: r['Max Severity'] ?? r['max severity'] ?? r['severity'],
    description: r['Description'] ?? r['description'],
    fixed_version: r['Fixed Version'] ?? r['fixed version'],
    mitigation: r['Mitigation'] ?? r['mitigation'],
  }))

  const normMultiple = multiple.map((r) => ({
    package: r['Package'] ?? r['package'],
    version: r['Version'] ?? r['version'],
    count: numOrNull(r['Count'] ?? r['count']),
    max_severity: r['Max Severity'] ?? r['max severity'] ?? r['severity'],
    description: r['Description'] ?? r['description'],
    fixed_version: r['Fixed Version'] ?? r['fixed version'],
    mitigation: r['Mitigation'] ?? r['mitigation'],
  }))

  const normVulns = vulns.map((r) => ({
    package: r['Package'] ?? r['package'],
    version: r['Version'] ?? r['version'],
    vuln_id: r['Vulnerability ID'] ?? r['vulnerability id'] ?? r['id'] ?? r['cve'] ?? '',
    severity: r['Severity'] ?? r['severity'],
    epss: r['EPSS Score'] ?? r['epss score'] ?? r['epss'] ?? 'N/A',
    description: r['Description'] ?? r['description'],
    fixed_version: r['Fixed Version'] ?? r['fixed version'],
    mitigation: r['Mitigation'] ?? r['mitigation'],
  }))

  return { summary: normSummary, multiple: normMultiple, vulns: normVulns }
}

function numOrNull(v: any): number | null {
  const n = Number(v)
  return Number.isFinite(n) ? n : null
}

function parseTableSection(md: string, headerRe: RegExp): any[] | null {
  const lines = md.split(/\r?\n/)
  let i = 0
  while (i < lines.length) {
    if (headerRe.test(lines[i])) break
    i++
  }
  if (i >= lines.length) return null
  // Seek to header row '|' and separator
  while (i < lines.length && !/^\|/.test(lines[i])) i++
  if (i >= lines.length) return []
  const headerLine = lines[i++]
  if (i >= lines.length) return []
  const sepLine = lines[i++]
  if (!/^\|\s*-/.test(sepLine)) return []
  const headers = splitRow(headerLine)
  const rows: any[] = []
  while (i < lines.length) {
    const line = lines[i]
    if (!/^\|/.test(line)) break
    const cells = splitRow(line)
    const obj: any = {}
    for (let c = 0; c < headers.length && c < cells.length; c++) {
      const key = headers[c]
      obj[key] = cells[c]
    }
    rows.push(obj)
    i++
  }
  return rows
}

function splitRow(line: string): string[] {
  // Remove leading/trailing pipes, split, and trim
  const parts = line.replace(/^\|/, '').replace(/\|$/, '').split('|')
  return parts.map((p) => p.trim())
}

function normSeverity(s: any): 'Critical' | 'High' | 'Medium' | 'Low' | 'Unknown' {
  const v = String(s || '').trim().toLowerCase()
  if (v.startsWith('crit')) return 'Critical'
  if (v.startsWith('hi')) return 'High'
  if (v.startsWith('med')) return 'Medium'
  if (v.startsWith('lo')) return 'Low'
  return 'Unknown'
}

function linkForVulnId(id: string): string | null {
  if (!id) return null
  const s = id.trim()
  if (/^CVE-\d{4}-\d{4,7}$/i.test(s)) {
    return `https://nvd.nist.gov/vuln/detail/${s.toUpperCase()}`
  }
  if (/^GHSA-/i.test(s)) {
    return `https://github.com/advisories/${s.toUpperCase()}`
  }
  if (/^PYSEC-\d{4}-\d{1,6}$/i.test(s)) {
    return `https://osv.dev/vulnerability/${s.toUpperCase()}`
  }
  if (/^RUBYSEC-\d{4}-\d{1,6}$/i.test(s)) {
    return `https://osv.dev/vulnerability/${s.toUpperCase()}`
  }
  if (/^GO-\d{4}-\d{1,6}$/i.test(s)) {
    return `https://osv.dev/vulnerability/${s.toUpperCase()}`
  }
  if (/^RUSTSEC-\d{4}-\d{1,6}$/i.test(s)) {
    return `https://osv.dev/vulnerability/${s.toUpperCase()}`
  }
  // Generic OSV search fallback for unknown formats
  return `https://osv.dev/search?q=${encodeURIComponent(s)}`
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
  return <span className={`px-2 py-0.5 rounded text-white ${severityBgClass(label)}`}>{label}</span>
}
