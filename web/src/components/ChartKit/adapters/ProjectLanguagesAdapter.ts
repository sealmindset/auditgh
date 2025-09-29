import { xhrGetJsonAbortable } from '../../../lib/xhr'
import type { AdapterParams, AnySeries, ChartType, DatasetAdapter, TreeNode } from '../types'
import { pieToTreeRoot } from './utils'

export const ProjectLanguagesAdapter: DatasetAdapter = {
  defaultType: 'donut',
  availableTypes: ['donut','pie','treemap','sunburst','bar'],
  async fetcher(params: AdapterParams, signal?: AbortSignal): Promise<any> {
    const base = window.location.origin
    const uuid = params?.projectId
    if (!uuid) return []
    const url = `${base}/db/project_languages?select=language,bytes,loc,files,is_primary&project_id=eq.${encodeURIComponent(String(uuid))}&order=bytes.desc`
    const rows = await xhrGetJsonAbortable(url, signal)
    return Array.isArray(rows) ? rows : []
  },
  toSeriesFor(type: ChartType, raw: any): AnySeries {
    const rows: Array<any> = Array.isArray(raw) ? raw : []
    const totals = new Map<string, number>()
    for (const r of rows) {
      const key = (r.language || 'Unknown') as string
      const val = Number(r.bytes || 0) // default metric: bytes
      totals.set(key, (totals.get(key) || 0) + val)
    }
    const pie = Array.from(totals.entries()).map(([k,v]) => ({ id: k, label: k, value: v }))
    if (type === 'donut' || type === 'pie') return { kind: 'pie', data: pie }
    if (type === 'treemap' || type === 'sunburst') {
      const root: TreeNode = pieToTreeRoot('Languages', pie)
      return { kind: 'tree', data: root }
    }
    if (type === 'bar') {
      const data = Array.from(totals.entries()).sort((a,b)=>b[1]-a[1]).map(([k,v]) => ({ index: k, value: v }))
      return { kind: 'bar', data: { data, keys: ['value'], indexBy: 'index' } }
    }
    return { kind: 'pie', data: pie }
  },
  isSupported(): { ok: true } { return { ok: true } },
  csv(raw: any): string {
    const rows: Array<any> = Array.isArray(raw) ? raw : []
    return 'language,bytes,loc,files\n' + rows.map(r => `${r.language||'Unknown'},${Number(r.bytes||0)},${Number(r.loc||0)},${Number(r.files||0)}`).join('\n')
  },
}
