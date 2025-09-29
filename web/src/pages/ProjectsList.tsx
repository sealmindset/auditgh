import { useEffect, useMemo, useState } from 'react'
import { xhrGetJson, xhrPostJson } from '../lib/xhr'
import DataTable, { ColumnDef } from '../components/DataTable'

export type ApiProject = { id: number; uuid: string; name: string; repo_url: string | null; description: string | null; is_active: boolean; created_at: string; primary_language: string | null; total_loc: number | null; stars?: number | null; forks?: number | null }

export default function ProjectsList() {
  const [items, setItems] = useState<ApiProject[]>([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [archiving, setArchiving] = useState<string | null>(null)
  const base = useMemo(() => window.location.origin, [])

  const [sortBy, setSortBy] = useState<'name' | 'total_loc'>('name')
  // CodeQL org totals + per-project severity mapping for filtering
  const [orgTotals, setOrgTotals] = useState<{ total: number; critical: number; high: number; medium: number; low: number; info: number; unknown: number }>({ total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0, unknown: 0 })
  // per-project severity counts aggregated across repos
  const [projSevMap, setProjSevMap] = useState<Record<string, { critical: number; high: number; medium: number; low: number; info: number; unknown: number }>>({})
  const defaultSeverities = useMemo(() => ["critical","high","medium","low","info","unknown"] as const, [])
  const [sevFilter, setSevFilter] = useState<string[]>([...defaultSeverities])

  useEffect(() => {
    setLoading(true)
    xhrGetJson(`${base}/db/projects?select=id,uuid,name,repo_url,description,is_active,primary_language,total_loc,stars,forks,created_at&order=name.asc`)
      .then((rows) => setItems(rows || []))
      .catch((err: any) => setError(err?.message || 'Failed to load projects'))
      .finally(() => setLoading(false))
  }, [base])

  // Load org severity totals and per-project severity from API views
  useEffect(() => {
    // Org totals
    xhrGetJson(`${base}/db/api.codeql_org_severity_totals?select=total,critical,high,medium,low,info,unknown`)
      .then((rows) => {
        const r = (rows || [])[0] || {}
        setOrgTotals({
          total: Number(r.total || 0),
          critical: Number(r.critical || 0),
          high: Number(r.high || 0),
          medium: Number(r.medium || 0),
          low: Number(r.low || 0),
          info: Number(r.info || 0),
          unknown: Number(r.unknown || 0),
        })
      })
      .catch(() => setOrgTotals({ total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0, unknown: 0 }))
    // Aggregate severity per project_id by summing across repos
    xhrGetJson(`${base}/db/api.codeql_org_top_repos?select=project_id,critical,high,medium,low,info,total`)
      .then((rows) => {
        const map: Record<string, { critical: number; high: number; medium: number; low: number; info: number; unknown: number }> = {}
        for (const r of rows || []) {
          const pid = (r.project_id || '').toString().trim()
          if (!pid) continue
          if (!map[pid]) map[pid] = { critical: 0, high: 0, medium: 0, low: 0, info: 0, unknown: 0 }
          map[pid].critical += Number(r.critical || 0)
          map[pid].high += Number(r.high || 0)
          map[pid].medium += Number(r.medium || 0)
          map[pid].low += Number(r.low || 0)
          map[pid].info += Number(r.info || 0)
        }
        setProjSevMap(map)
      })
      .catch(() => setProjSevMap({}))
  }, [base])

  async function archiveProject(p: ApiProject) {
    if (!confirm(`Archive project: ${p.name}?`)) return
    setArchiving(p.uuid)
    try {
      await xhrPostJson(`${base}/db/rpc/update_project`, {
        p_uuid: p.uuid,
        p_name: p.name,
        p_repo_url: p.repo_url,
        p_description: p.description,
        p_is_active: false,
      })
      setItems((prev) => prev.map((it) => (it.uuid === p.uuid ? { ...it, is_active: false } : it)))
    } catch (e: any) {
      setError(e?.message || 'Failed to archive project')
    } finally {
      setArchiving(null)
    }
  }

  const columns: ColumnDef<ApiProject>[] = [
    {
      key: 'name',
      header: 'Name',
      filter: { type: 'text', getValue: (row) => String(row.name || '') },
      render: (row) => (
        <a href={`/projects/${row.uuid}?id=${row.id}`} className="text-blue-700 hover:underline">{row.name}</a>
      ),
    },
    { key: 'description', header: 'Description', sortable: false, filter: { type: 'text', getValue: (row) => String(row.description || '') } },
    {
      key: 'primary_language',
      header: 'Primary Language',
      filter: { type: 'enum', getValue: (row) => String(row.primary_language || '') },
      render: (row) => (
        row.primary_language ? (
          <span className="inline-block rounded border border-slate-200 bg-slate-100 px-2 py-0.5 text-xs">
            {row.primary_language}
          </span>
        ) : (
          <span className="text-slate-400 text-xs">—</span>
        )
      ),
    },
    {
      key: 'total_loc',
      header: 'Total LOC',
      render: (row) => (row.total_loc != null ? row.total_loc.toLocaleString() : '—'),
      widthClass: 'w-32',
    },
    {
      key: 'stars',
      header: 'Stars',
      render: (row) => (typeof row.stars === 'number' ? row.stars.toLocaleString() : '—'),
      widthClass: 'w-24',
    },
    {
      key: 'forks',
      header: 'Forks',
      render: (row) => (typeof row.forks === 'number' ? row.forks.toLocaleString() : '—'),
      widthClass: 'w-24',
    },
    {
      key: 'is_active',
      header: 'Status',
      filter: { type: 'enum', enumValues: ['Active','Archived'], getValue: (row) => (row.is_active ? 'Active' : 'Archived') },
      render: (row) => (row.is_active ? <span className="text-green-700">Active</span> : <span className="text-slate-500">Archived</span>),
    },
    {
      key: 'created_at',
      header: 'Created',
      render: (row) => new Date(row.created_at).toLocaleDateString(),
    },
    {
      key: 'actions',
      header: 'Actions',
      sortable: false,
      render: (row) => (
        <div className="flex gap-2">
          <a href={`/projects/${row.uuid}?id=${row.id}`} className="border border-blue-300 text-blue-700 px-2 py-0.5 rounded text-xs">View</a>
          {row.is_active ? (
            <button
              className="border border-red-300 text-red-700 px-2 py-0.5 rounded text-xs disabled:opacity-50"
              onClick={() => archiveProject(row)}
              disabled={archiving === row.uuid}
            >
              {archiving === row.uuid ? 'Archiving…' : 'Archive'}
            </button>
          ) : (
            <span className="text-slate-400 text-xs">—</span>
          )}
        </div>
      ),
    },
  ]

  const displayItems = useMemo(() => {
    const arr = [...items]
    if (sortBy === 'total_loc') {
      arr.sort((a, b) => (b.total_loc || 0) - (a.total_loc || 0) || a.name.localeCompare(b.name))
    } else {
      arr.sort((a, b) => a.name.localeCompare(b.name))
    }
    // Apply severity filter if not "All"
    if (sevFilter.length !== defaultSeverities.length) {
      const selected = new Set(sevFilter.map((s) => s.toLowerCase()))
      return arr.filter((p) => {
        const sev = projSevMap[p.uuid]
        if (!sev) return false
        // include if any selected severity has count > 0
        return (
          (selected.has('critical') && (sev.critical || 0) > 0) ||
          (selected.has('high') && (sev.high || 0) > 0) ||
          (selected.has('medium') && (sev.medium || 0) > 0) ||
          (selected.has('low') && (sev.low || 0) > 0) ||
          (selected.has('info') && (sev.info || 0) > 0) ||
          (selected.has('unknown') && (sev.unknown || 0) > 0)
        )
      })
    }
    return arr
  }, [items, sortBy, sevFilter, defaultSeverities.length, projSevMap])

  return (
    <div className="min-h-screen bg-slate-50 text-slate-900">
      <header className="flex items-center justify-between p-4 border-b bg-white sticky top-0">
        <h1 className="font-semibold">Projects</h1>
      </header>
      <main className="p-4 space-y-4">
        {/* CodeQL Severity Totals removed */}
        <div className="flex items-center justify-between text-sm">
          <div className="invisible">.</div>
          <label className="flex items-center gap-2">
            <span>Sort by:</span>
            <select className="border rounded px-2 py-1" value={sortBy} onChange={(e) => setSortBy(e.target.value as 'name' | 'total_loc')}>
              <option value="name">Name (A→Z)</option>
              <option value="total_loc">Total LOC (high→low)</option>
            </select>
          </label>
        </div>
        {error && (
          <div role="alert" className="border rounded p-3 bg-red-50 border-red-200 text-red-700">{error}</div>
        )}
        {loading ? (
          <div className="bg-white p-4 rounded shadow-sm text-slate-500">Loading…</div>
        ) : (
          <DataTable
            data={displayItems}
            columns={columns}
            pageSizeOptions={[10, 25, 50]}
            defaultPageSize={10}
            filterKeys={['name', 'description', 'primary_language', 'total_loc']}
            searchPlaceholder="Search projects…"
          />
        )}
      </main>
    </div>
  )
}
