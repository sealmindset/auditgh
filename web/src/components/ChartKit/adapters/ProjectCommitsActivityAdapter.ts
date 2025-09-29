import { xhrGetJsonAbortable } from '../../../lib/xhr'
import type { AdapterParams, AnySeries, ChartType, DatasetAdapter } from '../types'
import { bucketByDay, mapToLineSeries } from './utils'

export const ProjectCommitsActivityAdapter: DatasetAdapter = {
  defaultType: 'line',
  availableTypes: ['line','bar'],
  async fetcher(params: AdapterParams, signal?: AbortSignal): Promise<any> {
    const base = window.location.origin
    const uuid = params?.projectId
    if (!uuid) return []
    const url = `${base}/db/project_commits?select=committed_at&project_id=eq.${encodeURIComponent(String(uuid))}&order=committed_at.desc&limit=500`
    const rows = await xhrGetJsonAbortable(url, signal)
    return Array.isArray(rows) ? rows : []
  },
  toSeriesFor(type: ChartType, raw: any, params: AdapterParams): AnySeries {
    const rows: Array<any> = Array.isArray(raw) ? raw : []
    const since = params?.since ? new Date(params.since) : null
    const filtered = since ? rows.filter(r => r.committed_at && new Date(r.committed_at) >= since) : rows
    const byDay = bucketByDay(filtered, (r) => r.committed_at ? new Date(r.committed_at) : null)

    if (type === 'line') {
      return { kind: 'line', data: mapToLineSeries('Commits', byDay) }
    }
    if (type === 'bar') {
      const data = Array.from(byDay.entries()).sort(([a],[b]) => a.localeCompare(b)).map(([k,v]) => ({ index: k, value: v }))
      return { kind: 'bar', data: { data, keys: ['value'], indexBy: 'index' } }
    }
    return { kind: 'line', data: mapToLineSeries('Commits', byDay) }
  },
  isSupported(type: ChartType, _raw: any, params: AdapterParams) {
    if (!params?.projectId) return { ok: false, reason: 'Select a project' }
    return { ok: true }
  },
  csv(_raw: any, series: AnySeries): string {
    if (series.kind === 'line') {
      const pts = series.data[0]?.data || []
      return 'date,value\n' + pts.map((p:any) => `${p.x},${p.y}`).join('\n')
    }
    return ''
  },
}
