import React from 'react'
import ChartSwitch from './ChartSwitch'
import { toPNG, toSVG } from './exporters'
import type { AdapterParams, AnySeries, ChartType, DatasetAdapter } from './types'
import DonutChart from './charts/Donut'
import BarChart from './charts/Bar'
import StackedBarChart from './charts/StackedBar'
import LineChart from './charts/Line'
import TreemapChart from './charts/Treemap'
import SunburstChart from './charts/Sunburst'
import BulletChart from './charts/Bullet'
import KPIs from './charts/KPIs'
import Loading from './Loading'
import ErrorState from './Error'
import EmptyState from './Empty'
import useDataset from './useDataset'

function tfKey(datasetKey: string) { return `chartkit.tf:${datasetKey}` }

export default function ChartHost({
  datasetKey,
  title,
  description,
  adapter,
  defaultType,
  availableTypes,
  params: paramsIn,
  timeRangeOptions = [7,14,30,90,0],
}: {
  datasetKey: string
  title: string
  description?: string
  adapter: DatasetAdapter
  defaultType?: ChartType
  availableTypes: ChartType[]
  params?: AdapterParams
  timeRangeOptions?: number[] // days; 0 = All
}) {
  const containerRef = React.useRef<HTMLDivElement>(null)
  const [type, setType] = React.useState<ChartType>(defaultType || adapter.defaultType)
  const [tfDays, setTfDays] = React.useState<number>(() => {
    try { const v = localStorage.getItem(tfKey(datasetKey)); return v ? Number(v) : 30 } catch { return 30 }
  })

  React.useEffect(() => {
    try { localStorage.setItem(tfKey(datasetKey), String(tfDays)) } catch {}
  }, [datasetKey, tfDays])

  const params: AdapterParams = React.useMemo(() => {
    if (tfDays && tfDays > 0) {
      const d = new Date()
      d.setDate(d.getDate() - tfDays)
      return { ...(paramsIn || {}), since: d.toISOString() }
    }
    return { ...(paramsIn || {}) }
  }, [paramsIn, tfDays])

  const { data: raw, loading, error, refresh } = useDataset(adapter.fetcher, params)

  const support = React.useMemo(() => adapter.isSupported(type, raw, params), [adapter, type, raw, params])
  const series: AnySeries | null = React.useMemo(() => {
    if (!raw || (Array.isArray(raw) && raw.length === 0)) return null
    if (support && (support as any).ok === false) return null
    try { return adapter.toSeriesFor(type, raw, params) } catch { return null }
  }, [adapter, type, raw, params, support])

  function handleExportPNG() {
    if (!containerRef.current) return
    toPNG(containerRef.current, `${datasetKey}-${type}.png`).catch(() => {})
  }
  function handleExportSVG() {
    if (!containerRef.current) return
    const svg = containerRef.current.querySelector('svg') as SVGElement | null
    if (svg) toSVG(svg, `${datasetKey}-${type}.svg`)
  }
  function handleExportCSV() {
    if (!series) return
    try {
      const csv = adapter.csv(raw, series, params)
      const blob = new Blob([csv], { type: 'text/csv;charset=utf-8' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `${datasetKey}-${type}.csv`
      a.click()
      setTimeout(() => URL.revokeObjectURL(url), 1000)
    } catch {}
  }

  return (
    <section className="bg-white p-4 rounded border">
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2">
          <h2 className="font-medium">{title}</h2>
          {description ? (
            <span
              className="text-xs text-slate-500 cursor-help"
              title={description}
              aria-label="Description"
            >ⓘ</span>
          ) : null}
        </div>
        <div className="flex items-center gap-2 text-xs">
          <ChartSwitch datasetKey={datasetKey} types={availableTypes} value={type} onChange={setType} />
          {timeRangeOptions && timeRangeOptions.length ? (
            <div className="inline-flex items-center gap-1">
              <label htmlFor={`tf-${datasetKey}`}>Range</label>
              <select
                id={`tf-${datasetKey}`}
                aria-label="Timeframe"
                className="text-xs border rounded px-2 py-1 bg-white focus:outline-none focus:ring-2 focus:ring-blue-500"
                value={tfDays}
                onChange={(e)=> setTfDays(Number(e.target.value))}
              >
                {timeRangeOptions.map((d) => (
                  <option key={d} value={d}>{d === 0 ? 'All' : `Last ${d}d`}</option>
                ))}
              </select>
            </div>
          ) : null}
          <div className="inline-flex items-center gap-1">
            <button type="button" className="px-2 py-1 border rounded bg-slate-100 hover:bg-slate-200" onClick={handleExportPNG}>PNG</button>
            <button type="button" className="px-2 py-1 border rounded bg-slate-100 hover:bg-slate-200" onClick={handleExportSVG}>SVG</button>
            <button type="button" className="px-2 py-1 border rounded bg-slate-100 hover:bg-slate-200" onClick={handleExportCSV}>CSV</button>
            <button type="button" className="px-2 py-1 border rounded bg-white hover:bg-slate-50" onClick={refresh}>Refresh</button>
          </div>
        </div>
      </div>

      <div ref={containerRef} className="min-h-[220px]">
        {loading ? <Loading /> : null}
        {!loading && error ? <ErrorState message={String(error?.message || error)} onRetry={refresh} /> : null}
        {!loading && !error && (!raw || (Array.isArray(raw) && raw.length === 0)) ? <EmptyState message="No data for selected filters" /> : null}
        {!loading && !error && raw ? (
          (support as any)?.ok === false ? (
            <EmptyState message={(support as any).reason || 'Chart type not supported for this dataset'} />
          ) : series ? (
            <ChartRenderer type={type} series={series} ariaLabel={title} />
          ) : (
            <EmptyState message="No data available" />
          )
        ) : null}
      </div>
    </section>
  )
}

function ChartRenderer({ type, series, ariaLabel }: { type: ChartType; series: AnySeries; ariaLabel: string }) {
  switch (type) {
    case 'donut':
      if (series.kind === 'pie') return <DonutChart ariaLabel={ariaLabel} data={series.data} innerRadius={0.6} />
      return <EmptyState message="Series mismatch for donut" />
    case 'pie':
      if (series.kind === 'pie') return <DonutChart ariaLabel={ariaLabel} data={series.data} innerRadius={0} />
      return <EmptyState message="Series mismatch for pie" />
    case 'bar':
      if (series.kind === 'bar') return <BarChart ariaLabel={ariaLabel} data={series.data} />
      return <EmptyState message="Series mismatch for bar" />
    case 'stackedBar':
      if (series.kind === 'bar') return <StackedBarChart ariaLabel={ariaLabel} data={series.data} />
      return <EmptyState message="Series mismatch for stacked bar" />
    case 'line':
      if (series.kind === 'line') return <LineChart ariaLabel={ariaLabel} data={series.data} />
      return <EmptyState message="Series mismatch for line" />
    case 'treemap':
      if (series.kind === 'tree') return <TreemapChart ariaLabel={ariaLabel} data={series.data} />
      return <EmptyState message="Series mismatch for treemap" />
    case 'sunburst':
      if (series.kind === 'tree') return <SunburstChart ariaLabel={ariaLabel} data={series.data} />
      return <EmptyState message="Series mismatch for sunburst" />
    case 'bullet':
      if (series.kind === 'bullet') return <BulletChart ariaLabel={ariaLabel} data={series.data} />
      return <EmptyState message="Series mismatch for bullet" />
    case 'kpis':
      if (series.kind === 'kpis') return <KPIs ariaLabel={ariaLabel} data={series.data} />
      return <EmptyState message="Series mismatch for KPIs" />
    default:
      return <EmptyState message="Unknown chart type" />
  }
}
