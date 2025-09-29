import { xhrGetJsonAbortable } from '../../../lib/xhr'
import type { AdapterParams, AnySeries, ChartType, DatasetAdapter } from '../types'
import { bucketByDay, mapToLineSeries } from './utils'

export const OrgProjectsContributorsAdapter: DatasetAdapter = {
  defaultType: 'bar',
  availableTypes: ['bar','donut','line'],
  async fetcher(params: AdapterParams, signal?: AbortSignal): Promise<any> {
    const base = window.location.origin
    const url = `${base}/db/project_commits?select=author_login,committed_at&order=committed_at.desc&limit=500`
    const rows = await xhrGetJsonAbortable(url, signal)
    return Array.isArray(rows) ? rows : []
  },
  toSeriesFor(type: ChartType, raw: any): AnySeries {
    const rows: Array<any> = Array.isArray(raw) ? raw : []
    const counts = new Map<string, number>()
    for (const r of rows) {
      const k = String(r.author_login || '(unknown)')
      counts.set(k, (counts.get(k) || 0) + 1)
    }
    const sorted = Array.from(counts.entries()).sort((a,b) => b[1]-a[1]).slice(0, 20)
    if (type === 'bar') {
      const data = sorted.map(([login, commits]) => ({ index: login, commits }))
      return { kind: 'bar', data: { data, keys: ['commits'], indexBy: 'index' } }
    }
    if (type === 'donut') {
      const pie = sorted.map(([login, commits]) => ({ id: login, label: login, value: commits }))
      return { kind: 'pie', data: pie }
    }
    if (type === 'line') {
      const byDay = bucketByDay(rows, (r) => r.committed_at ? new Date(r.committed_at) : null)
      return { kind: 'line', data: mapToLineSeries('Commits', byDay) }
    }
    const data = sorted.map(([login, commits]) => ({ index: login, commits }))
    return { kind: 'bar', data: { data, keys: ['commits'], indexBy: 'index' } }
  },
  isSupported(): { ok: true } { return { ok: true } },
  csv(raw: any): string {
    const rows: Array<any> = Array.isArray(raw) ? raw : []
    const counts = new Map<string, number>()
    for (const r of rows) { const k = String(r.author_login || '(unknown)'); counts.set(k, (counts.get(k) || 0) + 1) }
    return 'login,commits\n' + Array.from(counts.entries()).map(([k,v]) => `${k},${v}`).join('\n')
  },
}
