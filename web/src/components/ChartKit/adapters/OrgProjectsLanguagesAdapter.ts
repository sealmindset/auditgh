import { xhrGetJsonAbortable } from '../../../lib/xhr'
import type { AdapterParams, AnySeries, ChartType, DatasetAdapter } from '../types'
import { pieToTreeRoot } from './utils'

export const OrgProjectsLanguagesAdapter: DatasetAdapter = {
  defaultType: 'donut',
  availableTypes: ['donut','treemap','sunburst','pie'],
  async fetcher(params: AdapterParams, signal?: AbortSignal): Promise<any> {
    const base = window.location.origin
    const url = `${base}/db/projects?select=primary_language&order=name.asc`
    const rows = await xhrGetJsonAbortable(url, signal)
    return Array.isArray(rows) ? rows : []
  },
  toSeriesFor(type: ChartType, raw: any): AnySeries {
    const rows: Array<any> = Array.isArray(raw) ? raw : []
    const counts = new Map<string, number>()
    for (const r of rows) {
      const key = (r.primary_language || 'Unknown') as string
      counts.set(key, (counts.get(key) || 0) + 1)
    }
    const pie = Array.from(counts.entries()).map(([k,v]) => ({ id: k, label: k, value: v }))
    if (type === 'donut' || type === 'pie') return { kind: 'pie', data: pie }
    const root = pieToTreeRoot('Languages', pie)
    return { kind: 'tree', data: root }
  },
  isSupported(): { ok: true } { return { ok: true } },
  csv(raw: any): string {
    const rows: Array<any> = Array.isArray(raw) ? raw : []
    const counts: Record<string, number> = {}
    for (const r of rows) { const k = r.primary_language || 'Unknown'; counts[k] = (counts[k] || 0) + 1 }
    const header = 'language,count\n'
    return header + Object.entries(counts).map(([k,v]) => `${k},${v}`).join('\n')
  },
}
