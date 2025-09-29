import { xhrGetJsonAbortable } from '../../../lib/xhr'
import type { AdapterParams, AnySeries, ChartType, DatasetAdapter, KPISeries } from '../types'

function endpoint(base: string) { return `${base}/api/dashboard/summary` }

export const OrgKPIsAdapter: DatasetAdapter = {
  defaultType: 'kpis',
  availableTypes: ['kpis','bar','bullet'],
  async fetcher(params: AdapterParams, signal?: AbortSignal): Promise<any> {
    const base = window.location.origin
    const data = await xhrGetJsonAbortable(endpoint(base), signal)
    return data?.data || null
  },
  toSeriesFor(type: ChartType, raw: any): AnySeries {
    const st = raw?.severity_totals || {}
    const total = Number(st.total || (st.critical + st.high + st.medium + st.low + st.info + st.unknown) || 0)
    const projects = Number(raw?.projects_count || 0)
    const repos = Number(raw?.repos_count || 0)
    const scans = Number(raw?.scans_count || 0)

    if (type === 'kpis') {
      const kpis: KPISeries = [
        { label: 'Projects', value: projects },
        { label: 'CodeQL Scanned', value: repos },
        { label: 'Scans', value: scans },
        { label: 'Findings', value: total },
      ]
      return { kind: 'kpis', data: kpis }
    }
    if (type === 'bar') {
      const data = [
        { index: 'Projects', value: projects },
        { index: 'Repos', value: repos },
        { index: 'Scans', value: scans },
        { index: 'Findings', value: total },
      ]
      return { kind: 'bar', data: { data, keys: ['value'], indexBy: 'index' } }
    }
    if (type === 'bullet') {
      // Heuristic targets (can be parameterized via ChartHost params later)
      const series = [
        { id: 'Projects', ranges: [projects * 0.5, projects, projects * 1.5], measures: [projects], markers: [projects] },
        { id: 'Repos', ranges: [repos * 0.5, repos, repos * 1.5], measures: [repos], markers: [repos] },
        { id: 'Scans', ranges: [scans * 0.5, scans, scans * 1.5], measures: [scans], markers: [scans] },
        { id: 'Findings', ranges: [0, total, total * 2], measures: [total], markers: [total] },
      ]
      return { kind: 'bullet', data: series }
    }
    // Fallback to KPIs
    return { kind: 'kpis', data: [
      { label: 'Projects', value: projects },
      { label: 'CodeQL Scanned', value: repos },
      { label: 'Scans', value: scans },
      { label: 'Findings', value: total },
    ] }
  },
  isSupported(): { ok: true } { return { ok: true } },
  csv(raw: any): string {
    const st = raw?.severity_totals || {}
    const total = Number(st.total || (st.critical + st.high + st.medium + st.low + st.info + st.unknown) || 0)
    const projects = Number(raw?.projects_count || 0)
    const repos = Number(raw?.repos_count || 0)
    const scans = Number(raw?.scans_count || 0)
    const rows = [
      { metric: 'Projects', value: projects },
      { metric: 'CodeQL Scanned', value: repos },
      { metric: 'Scans', value: scans },
      { metric: 'Findings', value: total },
    ]
    return 'metric,value\n' + rows.map(r => `${r.metric},${r.value}`).join('\n')
  },
}
