import React, { useEffect, useMemo, useState } from 'react'
import DataTable, { ColumnDef } from './DataTable'
import { xhrGetJson } from '../lib/xhr'

export default function BinariesTable({ projectId, repoName, onRequestFullscreen }: { projectId: string; repoName: string | null; onRequestFullscreen?: (cfg: { id: string; name: string; fields?: Array<{key:string;label:string}>; columns?: ColumnDef<any>[]; rows: any[] }) => void }) {
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [rows, setRows] = useState<any[]>([])

  const jsonPath = useMemo(() => (repoName ? `/binaries_reports/${repoName}/${repoName}_binaries.json` : null), [repoName])
  const mdPath = useMemo(() => (repoName ? `/binaries_reports/${repoName}/${repoName}_binaries.md` : null), [repoName])

  useEffect(() => {
    if (!projectId || !repoName) return
    let canceled = false
    async function loadPreferred() {
      setLoading(true)
      setError(null)
      try {
        // Prefer DB via PostgREST
        const sel = 'path,filename,extension,size_bytes,is_executable,type,sha256,mode,created_at'
        let url = `/db/binaries_findings?select=${encodeURIComponent(sel)}&project_id=eq.${encodeURIComponent(projectId)}&order=created_at.desc`
        if (repoName) url += `&repo_short=eq.${encodeURIComponent(repoName)}`
        const data = await xhrGetJson(url)
        const items = Array.isArray(data) ? data : []
        if (!canceled && items.length > 0) { setRows(items); return }
        // Fallback to static JSON if DB is empty
        if (jsonPath) {
          try {
            const staticData = await xhrGetJson(jsonPath)
            const rows = Array.isArray(staticData?.findings) ? staticData.findings : []
            if (!canceled) setRows(rows)
          } catch (e: any) {
            if (!canceled) setError(e?.message || 'Failed to load binaries report')
          }
        }
      } catch (e: any) {
        // DB error; try static
        if (jsonPath) {
          try {
            const staticData = await xhrGetJson(jsonPath)
            const rows = Array.isArray(staticData?.findings) ? staticData.findings : []
            if (!canceled) setRows(rows)
          } catch (e2: any) {
            if (!canceled) setError(e2?.message || 'Failed to load binaries report')
          }
        } else {
          if (!canceled) setError(e?.message || 'Failed to load binaries report')
        }
      } finally {
        if (!canceled) setLoading(false)
      }
    }
    // eslint-disable-next-line @typescript-eslint/no-floating-promises
    loadPreferred()
    return () => { canceled = true }
  }, [projectId, repoName, jsonPath])

  const totalCount = rows.length
  const execCount = rows.reduce((s, r) => s + (r?.is_executable ? 1 : 0), 0)

  const columns: ColumnDef<any>[] = [
    { key: 'filename', header: 'Filename', sortable: true, filter: { type: 'text', getValue: (r) => String(r.filename || '') } },
    { key: 'path', header: 'Path', sortable: true, filter: { type: 'text', getValue: (r) => String(r.path || '') }, render: (r) => <code title={r.path || ''}>{r.path || ''}</code> },
    { key: 'extension', header: 'Ext', sortable: true, filter: { type: 'text', getValue: (r) => String(r.extension || '') } },
    { key: 'size_bytes', header: 'Size', sortable: true, filter: { type: 'text', getValue: (r) => String(r.size_bytes || 0) }, render: (r) => (typeof r.size_bytes === 'number' ? r.size_bytes.toLocaleString() : r.size_bytes) },
    { key: 'is_executable', header: 'Executable', sortable: true, filter: { type: 'enum', enumValues: ['Yes','No'], getValue: (r) => (r.is_executable ? 'Yes' : 'No') }, render: (r) => (r.is_executable ? 'Yes' : 'No') },
    { key: 'type', header: 'Type', sortable: true, filter: { type: 'text', getValue: (r) => String(r.type || '') } },
    { key: 'sha256', header: 'SHA256', sortable: false, filter: { type: 'text', getValue: (r) => String(r.sha256 || '') }, render: (r) => r.sha256 ? <code title={r.sha256}>{String(r.sha256).slice(0,12)}</code> : <span className="text-slate-400">—</span> },
    { key: 'mode', header: 'Mode', sortable: true, filter: { type: 'text', getValue: (r) => String(r.mode || '') } },
  ]

  return (
    <div className="bg-white p-4 rounded shadow-sm">
      <div className="flex items-center justify-between mb-2">
        <h2 className="font-medium">Binaries</h2>
        <div className="text-xs text-slate-600 flex items-center gap-3">
          <span>Total: <strong>{totalCount}</strong></span>
          <span>Executables: <strong>{execCount}</strong></span>
          {mdPath ? <a href={mdPath} target="_blank" rel="noreferrer" className="text-blue-600 underline">View Markdown</a> : null}
          {jsonPath ? <a href={jsonPath} target="_blank" rel="noreferrer" className="text-blue-600 underline">Download JSON</a> : null}
          <button
            type="button"
            className="px-2 py-1 border rounded bg-slate-100 hover:bg-slate-200"
            onClick={() => onRequestFullscreen && onRequestFullscreen({
              id: 'binaries',
              name: 'Binaries',
              columns,
              rows,
            })}
          >
            Fullscreen
          </button>
        </div>
      </div>
      {!repoName ? (
        <div className="text-sm text-slate-600">No repository URL set for this project.</div>
      ) : loading ? (
        <div className="text-sm text-slate-600">Loading…</div>
      ) : error ? (
        <div className="text-sm text-red-700">{error}</div>
      ) : rows.length === 0 ? (
        <div className="text-sm text-slate-600">No binaries found.</div>
      ) : (
        <DataTable
          data={rows}
          columns={columns}
          defaultPageSize={10}
          pageSizeOptions={[10,25,50]}
          filterKeys={["path","size_bytes","is_executable","type","sha256","mode"]}
          searchPlaceholder="Search binaries…"
        />
      )}
    </div>
  )
}
