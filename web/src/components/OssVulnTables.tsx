import React, { useEffect, useMemo, useState } from 'react'
import DataTable, { ColumnDef } from './DataTable'
import { xhrGetText } from '../lib/xhr'

// Simple in-memory cache to avoid re-fetching/parsing when navigating
const reportCache = new Map<string, { summary: any[]; multiple: any[]; vulns: any[] }>()

export default function OssVulnTables({ repoName }: { repoName: string | null }) {
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [summaryRows, setSummaryRows] = useState<any[]>([])
  const [multipleRows, setMultipleRows] = useState<any[]>([])
  const [vulnRows, setVulnRows] = useState<any[]>([])

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

  // Severity filter chips (applies to all three tables)
  const [sevFilter, setSevFilter] = useState<Record<string, boolean>>({
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

  const filteredSummary = useMemo(() => {
    return (summaryRows || []).filter((r) => sevFilter[normSeverity(r.max_severity)])
  }, [summaryRows, sevFilter])

  const filteredMultiple = useMemo(() => {
    return (multipleRows || []).filter((r) => sevFilter[normSeverity(r.max_severity)])
  }, [multipleRows, sevFilter])

  const filteredVulns = useMemo(() => {
    return (vulnRows || []).filter((r) => sevFilter[normSeverity(r.severity)])
  }, [vulnRows, sevFilter])

  const vulnTotals = useMemo(() => {
    const t: Record<'Critical'|'High'|'Medium'|'Low'|'Unknown', number> = { Critical: 0, High: 0, Medium: 0, Low: 0, Unknown: 0 }
    for (const r of (vulnRows || [])) t[normSeverity(r.severity)]++
    return t
  }, [vulnRows])

  const columnsSummary: ColumnDef<any>[] = [
    { key: 'package', header: 'Package' },
    { key: 'version', header: 'Version' },
    { key: 'count', header: 'Count' },
    {
      key: 'max_severity',
      header: 'Max Severity',
      render: (row) => <SeverityBadge severity={row.max_severity} />,
    },
    { key: 'description', header: 'Description', sortable: false },
    { key: 'fixed_version', header: 'Fixed Version' },
    { key: 'mitigation', header: 'Mitigation', sortable: false },
  ]

  const columnsMultiple: ColumnDef<any>[] = [
    { key: 'package', header: 'Package' },
    { key: 'version', header: 'Version' },
    { key: 'count', header: 'Count' },
    {
      key: 'max_severity',
      header: 'Max Severity',
      render: (row) => <SeverityBadge severity={row.max_severity} />,
    },
    { key: 'description', header: 'Description', sortable: false },
    { key: 'fixed_version', header: 'Fixed Version' },
    { key: 'mitigation', header: 'Mitigation', sortable: false },
  ]

  const columnsVulns: ColumnDef<any>[] = [
    { key: 'package', header: 'Package' },
    { key: 'version', header: 'Version' },
    {
      key: 'vuln_id',
      header: 'Vulnerability ID',
      render: (row) => {
        const id: string = row.vuln_id || ''
        const href = linkForVulnId(id)
        return href ? (
          <a href={href} target="_blank" rel="noreferrer" className="text-blue-600 hover:underline">{id}</a>
        ) : (id || '—')
      },
    },
    { key: 'severity', header: 'Severity', render: (row) => <SeverityBadge severity={row.severity} /> },
    { key: 'epss', header: 'EPSS Score' },
    { key: 'description', header: 'Description', sortable: false },
    { key: 'fixed_version', header: 'Fixed Version' },
    { key: 'mitigation', header: 'Mitigation', sortable: false },
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
          <div className="flex flex-wrap gap-2 items-center text-sm">
            <span className="mr-1">Severity:</span>
            {(['Critical','High','Medium','Low','Unknown'] as const).map((s) => (
              <button
                key={s}
                className={`px-2 py-0.5 rounded border ${sevFilter[s] ? 'bg-slate-200 border-slate-300 text-slate-900' : 'bg-white border-slate-200 text-slate-500'}`}
                onClick={() => toggleSev(s)}
              >
                {s}
              </button>
            ))}
            <span className="mx-1">|</span>
            <button className="px-2 py-0.5 rounded border bg-white border-slate-200 text-slate-600" onClick={() => setAll(true)}>All</button>
            <button className="px-2 py-0.5 rounded border bg-white border-slate-200 text-slate-600" onClick={() => setAll(false)}>None</button>
          </div>
          <div className="flex flex-wrap gap-2 items-center text-sm">
            <span className="mr-1">Totals:</span>
            {(['Critical','High','Medium','Low','Unknown'] as const).map((s) => (
              <span key={s} className={`px-2 py-0.5 rounded text-white ${severityBgClass(s)}`}>{s}: {vulnTotals[s] ?? 0}</span>
            ))}
          </div>
          <section>
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

          <section>
            <h3 className="font-medium mb-2">Multiple Vulnerabilities</h3>
            {multipleRows.length === 0 ? (
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
            )}
          </section>

          <section>
            <h3 className="font-medium mb-2">Vulnerabilities Found</h3>
            {vulnRows.length === 0 ? (
              <div className="text-sm text-slate-600">No vulnerabilities found.</div>
            ) : (
              <DataTable
                data={filteredVulns}
                columns={columnsVulns}
                pageSizeOptions={[10, 25, 50]}
                defaultPageSize={10}
                filterKeys={['package', 'version', 'vuln_id', 'severity', 'epss', 'description', 'fixed_version', 'mitigation']}
                searchPlaceholder="Search vulnerabilities…"
              />
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
