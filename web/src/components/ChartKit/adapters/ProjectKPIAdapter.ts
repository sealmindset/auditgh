import { xhrGetJsonAbortable } from '../../../lib/xhr'
import type { AdapterParams, AnySeries, ChartType, DatasetAdapter, KPISeries } from '../types'

export const ProjectKPIAdapter: DatasetAdapter = {
  defaultType: 'kpis',
  availableTypes: ['kpis','bar','bullet'],
  async fetcher(params: AdapterParams, signal?: AbortSignal): Promise<any> {
    const base = window.location.origin
    const uuid = params?.projectId
    if (!uuid) return null
    const url = `${base}/db/projects?select=uuid,name,stars,forks,contributors_count,last_commit_at,total_loc&uuid=eq.${encodeURIComponent(String(uuid))}&limit=1`
    const rows = await xhrGetJsonAbortable(url, signal)
    return Array.isArray(rows) && rows[0] ? rows[0] : null
  },
  toSeriesFor(type: ChartType, raw: any, params: AdapterParams): AnySeries {
    const stars = Number(raw?.stars || 0)
    const forks = Number(raw?.forks || 0)
    const contribs = Number(raw?.contributors_count || 0)
    const loc = Number(raw?.total_loc || 0)
    const last = raw?.last_commit_at ? new Date(raw.last_commit_at) : null
    const daysSince = last ? Math.max(0, Math.round((Date.now() - last.getTime()) / (1000*60*60*24))) : null

    if (type === 'kpis') {
      const kpis: KPISeries = [
        { label: 'Stars', value: stars },
        { label: 'Forks', value: forks },
        { label: 'Contributors', value: contribs },
        { label: 'Lines of Code', value: loc },
      ]
      return { kind: 'kpis', data: kpis }
    }
    if (type === 'bar') {
      const data = [
        { index: 'Stars', value: stars },
        { index: 'Forks', value: forks },
        { index: 'Contributors', value: contribs },
        { index: 'LOC', value: loc },
      ]
      return { kind: 'bar', data: { data, keys: ['value'], indexBy: 'index' } }
    }
    if (type === 'bullet') {
      const series = [
        { id: 'Stars', ranges: [stars * 0.5, stars, stars * 1.5], measures: [stars], markers: [stars] },
        { id: 'Forks', ranges: [forks * 0.5, forks, forks * 1.5], measures: [forks], markers: [forks] },
        { id: 'Contribs', ranges: [contribs * 0.5, contribs, contribs * 1.5], measures: [contribs], markers: [contribs] },
        { id: 'LOC', ranges: [loc * 0.5, loc, loc * 1.5], measures: [loc], markers: [loc] },
      ]
      return { kind: 'bullet', data: series }
    }
    return { kind: 'kpis', data: [
      { label: 'Stars', value: stars },
      { label: 'Forks', value: forks },
      { label: 'Contributors', value: contribs },
      { label: 'Lines of Code', value: loc },
    ] }
  },
  isSupported(): { ok: true } { return { ok: true } },
  csv(raw: any): string {
    const stars = Number(raw?.stars || 0)
    const forks = Number(raw?.forks || 0)
    const contribs = Number(raw?.contributors_count || 0)
    const loc = Number(raw?.total_loc || 0)
    const rows = [
      { metric: 'Stars', value: stars },
      { metric: 'Forks', value: forks },
      { metric: 'Contributors', value: contribs },
      { metric: 'Lines of Code', value: loc },
    ]
    return 'metric,value\n' + rows.map(r => `${r.metric},${r.value}`).join('\n')
  },
}
