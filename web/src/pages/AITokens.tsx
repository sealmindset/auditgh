import React, { useEffect, useMemo, useState } from 'react'
import { xhrGetJson } from '../lib/xhr'
import DataTable, { ColumnDef } from '../components/DataTable'

interface AiTokenRow {
  project_name: string
  provider: string
  token: string
  repo_short: string
  validation_status: string
  file_path?: string
  line_start?: number
  line_end?: number
  created_at: string
  updated_at: string
}

export default function AITokens() {
  const [rows, setRows] = useState<AiTokenRow[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string|undefined>()
  const [provider, setProvider] = useState<string>('')
  const [status, setStatus] = useState<string>('')

  const fetchData = async () => {
    setLoading(true)
    setError(undefined)
    try {
      const params = new URLSearchParams()
      if (provider) params.set('provider', provider)
      if (status) params.set('validation_status', status)
      const api = `/api/ai-tokens?${params.toString()}`
      const res = await xhrGetJson(api)
      setRows(res.items || [])
    } catch (e: any) {
      setError(String(e?.message || e))
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { fetchData() // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [provider, status])

  const columns: ColumnDef<AiTokenRow>[] = useMemo(() => [
    { key: 'project_name', header: 'Project', filter: { type: 'text', getValue: (r) => String(r.project_name || '') } },
    { key: 'provider', header: 'Provider', filter: { type: 'enum' } },
    { key: 'repo_short', header: 'Repo', filter: { type: 'text', getValue: (r) => String(r.repo_short || '') } },
    { key: 'token', header: 'Token', filter: { type: 'text', getValue: (r) => String(r.token || '') } },
    { key: 'validation_status', header: 'Validation', filter: { type: 'enum', enumValues: ['valid','invalid','error','unknown'], getValue: (r) => String(r.validation_status || 'unknown').toLowerCase() } },
    { key: 'file_path', header: 'File', filter: { type: 'text', getValue: (r) => String(r.file_path || '') } },
    { key: 'line_start', header: 'Line' },
    { key: 'created_at', header: 'Created' },
  ], [])

  return (
    <main className="max-w-screen-2xl mx-auto px-3 py-4">
      <h1 className="text-xl font-semibold mb-3">AI Tokens</h1>

      <div className="flex gap-2 items-end mb-3">
        <div>
          <label className="block text-xs text-gray-600">Provider</label>
          <input value={provider} onChange={e=>setProvider(e.target.value)} className="border rounded px-2 py-1 text-sm" placeholder="e.g., openai" />
        </div>
        <div>
          <label className="block text-xs text-gray-600">Validation</label>
          <select value={status} onChange={e=>setStatus(e.target.value)} className="border rounded px-2 py-1 text-sm">
            <option value="">(any)</option>
            <option value="valid">valid</option>
            <option value="invalid">invalid</option>
            <option value="error">error</option>
            <option value="unknown">unknown</option>
          </select>
        </div>
        <button onClick={fetchData} className="px-3 py-1 rounded bg-blue-600 text-white text-sm">Refresh</button>
      </div>

      {error && <div className="text-red-700 text-sm mb-2">{error}</div>}
      {loading ? <div className="text-sm">Loading…</div> : (
        <DataTable columns={columns} data={rows} />
      )}
    </main>
  )
}
