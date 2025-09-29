import { xhrGetJsonAbortable } from '../../../lib/xhr'
import type { AdapterParams, AnySeries, ChartType, DatasetAdapter } from '../types'
import { SEVERITY_ORDER, countsToPie, pieToTreeRoot } from './utils'

function endpoint(base: string) { return `${base}/api/dashboard/summary` }

export const OrgSeverityAdapter: DatasetAdapter = {
  defaultType: 'donut',
  availableTypes: ['donut','pie','bar','treemap','sunburst'],
  async fetcher(params: AdapterParams, signal?: AbortSignal): Promise<any> {
    const base = window.location.origin
    const data = await xhrGetJsonAbortable(endpoint(base), signal)
    return data?.data || null
  },
  toSeriesFor(type: ChartType, raw: any): AnySeries {
    const st = raw?.severity_totals || {}
    const counts: Record<string, number> = {
      Critical: Number(st.critical || 0),
      High: Number(st.high || 0),
      Medium: Number(st.medium || 0),
      Low: Number(st.low || 0),
      Info: Number(st.info || 0),
      Unknown: Number(st.unknown || 0),
    }
    const pie = countsToPie(counts)
    if (type === 'donut' || type === 'pie') return { kind: 'pie', data: pie }
    if (type === 'bar') {
      const data = SEVERITY_ORDER.map((sev) => ({ index: sev, count: counts[sev] || 0 }))
      return { kind: 'bar', data: { data, keys: ['count'], indexBy: 'index' } }
    }
    if (type === 'treemap' || type === 'sunburst') {
      const root = pieToTreeRoot('Severity', pie)
      return { kind: 'tree', data: root }
    }
    // Fallback
    return { kind: 'pie', data: pie }
  },
  isSupported(type: ChartType) {
    if (['line','bullet','kpis','stackedBar'].includes(type)) return { ok: false, reason: 'This dataset has no time or multi-series structure.' }
    return { ok: true }
  },
  csv(raw: any): string {
    const st = raw?.severity_totals || {}
    const rows = SEVERITY_ORDER.map((sev) => ({ severity: sev, value: Number((st as any)[sev.toLowerCase()] || 0) }))
    const header = 'severity,value\n'
    return header + rows.map(r => `${r.severity},${r.value}`).join('\n')
  },
}
