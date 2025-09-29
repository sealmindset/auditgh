import { xhrGetJsonAbortable } from '../../../lib/xhr'
import type { AdapterParams, AnySeries, ChartType, DatasetAdapter, TreeNode } from '../types'
import { SEVERITY_ORDER } from './utils'

function endpoint(base: string) { return `${base}/api/dashboard/top-repos?limit=10` }

export const TopReposAdapter: DatasetAdapter = {
  defaultType: 'stackedBar',
  availableTypes: ['stackedBar','treemap','sunburst','donut'],
  async fetcher(params: AdapterParams, signal?: AbortSignal): Promise<any> {
    const base = window.location.origin
    const data = await xhrGetJsonAbortable(endpoint(base), signal)
    return data?.data || []
  },
  toSeriesFor(type: ChartType, raw: any, params: AdapterParams): AnySeries {
    const rows: Array<any> = Array.isArray(raw) ? raw : []
    if (type === 'stackedBar') {
      const data = rows.map(r => ({
        index: r.repo,
        Critical: Number(r.critical || 0),
        High: Number(r.high || 0),
        Medium: Number(r.medium || 0),
        Low: Number(r.low || 0),
        Info: Number(r.info || 0),
      }))
      return { kind: 'bar', data: { data, keys: ['Critical','High','Medium','Low','Info'], indexBy: 'index' } }
    }
    if (type === 'treemap' || type === 'sunburst') {
      const root: TreeNode = { name: 'Repos', children: [] }
      root.children = rows.map(r => ({
        name: r.repo,
        children: SEVERITY_ORDER.map(sev => ({ name: sev, value: Number((r as any)[sev.toLowerCase()] || 0) }))
      }))
      return { kind: 'tree', data: root }
    }
    if (type === 'donut') {
      const repo: string | undefined = params?.repo
      if (!repo) {
        return { kind: 'pie', data: [] }
      }
      const r = rows.find((x) => String(x.repo) === String(repo))
      const data = SEVERITY_ORDER.map(sev => ({ id: sev, label: sev, value: Number(r?.[sev.toLowerCase()] || 0) }))
      return { kind: 'pie', data }
    }
    // Fallback
    const data = rows.map(r => ({ index: r.repo, total: Number(r.total || 0) }))
    return { kind: 'bar', data: { data, keys: ['total'], indexBy: 'index' } }
  },
  isSupported(type: ChartType, raw: any, params: AdapterParams) {
    if (type === 'donut' && !params?.repo) return { ok: false, reason: 'Select a repository to view a donut breakdown.' }
    return { ok: true }
  },
  csv(raw: any): string {
    const rows: any[] = Array.isArray(raw) ? raw : []
    const headers = ['repo','critical','high','medium','low','info','total']
    const toRow = (r: any) => headers.map(h => r[h] ?? '')
    return headers.join(',') + '\n' + rows.map(toRow).map(arr => arr.join(',')).join('\n')
  },
}
