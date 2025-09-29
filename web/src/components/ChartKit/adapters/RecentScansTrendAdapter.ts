import { xhrGetJsonAbortable } from '../../../lib/xhr'
import type { AdapterParams, AnySeries, ChartType, DatasetAdapter } from '../types'
import { bucketByDay, mapToLineSeries } from './utils'

function endpoint(base: string) { return `${base}/api/dashboard/recent-scans?limit=200` }

export const RecentScansTrendAdapter: DatasetAdapter = {
  defaultType: 'line',
  availableTypes: ['line','bar','bullet','donut'],
  async fetcher(params: AdapterParams, signal?: AbortSignal): Promise<any> {
    const base = window.location.origin
    const data = await xhrGetJsonAbortable(endpoint(base), signal)
    return data?.data || []
  },
  toSeriesFor(type: ChartType, raw: any, params: AdapterParams): AnySeries {
    const rows: Array<any> = Array.isArray(raw) ? raw : []
    const since = params?.since ? new Date(params.since) : null
    const filtered = since ? rows.filter(r => r.finished_at && new Date(r.finished_at) >= since) : rows

    const byDay = bucketByDay(filtered, (r) => r.finished_at ? new Date(r.finished_at) : null)

    if (type === 'line') {
      return { kind: 'line', data: mapToLineSeries('Findings', byDay) }
    }
    if (type === 'bar') {
      const data = Array.from(byDay.entries()).sort(([a],[b]) => a.localeCompare(b)).map(([k,v]) => ({ index: k, value: v }))
      return { kind: 'bar', data: { data, keys: ['value'], indexBy: 'index' } }
    }
    if (type === 'bullet') {
      const entries = Array.from(byDay.values())
      const todayKey = new Date().toISOString().slice(0,10)
      const today = byDay.get(todayKey) || 0
      const avg = entries.length ? entries.reduce((a,b)=>a+b,0) / entries.length : 0
      return { kind: 'bullet', data: [{ id: 'Today vs Avg', ranges: [avg * 0.5, avg, avg * 1.5], measures: [today], markers: [avg] }] }
    }
    if (type === 'donut') {
      // distribution buckets: 0, 1-10, 11-50, 51+
      const buckets = { '0': 0, '1-10': 0, '11-50': 0, '51+': 0 }
      for (const v of byDay.values()) {
        if (v === 0) buckets['0']++
        else if (v <= 10) buckets['1-10']++
        else if (v <= 50) buckets['11-50']++
        else buckets['51+']++
      }
      const data = Object.entries(buckets).map(([k,v]) => ({ id: k, label: k, value: v }))
      return { kind: 'pie', data }
    }
    return { kind: 'line', data: mapToLineSeries('Findings', byDay) }
  },
  isSupported(): { ok: true } { return { ok: true } },
  csv(raw: any, series: AnySeries): string {
    if (series.kind === 'line') {
      const pts = series.data[0]?.data || []
      return 'date,value\n' + pts.map(p => `${p.x},${p.y}`).join('\n')
    }
    return ''
  },
}
