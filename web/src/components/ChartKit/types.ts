import type { CSSProperties } from 'react'

export type ChartType =
  | 'donut'
  | 'pie'
  | 'bar'
  | 'stackedBar'
  | 'line'
  | 'treemap'
  | 'sunburst'
  | 'bullet'
  | 'kpis'

// Pie/Donut datum
export type PieDatum = { id: string; label?: string; value: number; color?: string }
export type PieSeries = PieDatum[]

// Bar/StackedBar datum
export type BarDatum = { index: string; [key: string]: string | number }
export type BarSeries = { data: BarDatum[]; keys: string[]; indexBy: 'index' }

// Line datum
export type LinePoint = { x: string | number | Date; y: number }
export type LineSerie = { id: string; data: LinePoint[] }
export type LineSeries = LineSerie[]

// Tree (Treemap/Sunburst)
export type TreeNode = { name: string; value?: number; children?: TreeNode[]; color?: string }

// Bullet datum
export type BulletDatum = { id: string; ranges: number[]; measures: number[]; markers?: number[] }
export type BulletSeries = BulletDatum[]

// KPI tiles
export type KPIDatum = { label: string; value: number; sublabel?: string; trend?: number; colorClass?: string }
export type KPISeries = KPIDatum[]

export type AnySeries =
  | { kind: 'pie'; data: PieSeries }
  | { kind: 'bar'; data: BarSeries }
  | { kind: 'line'; data: LineSeries }
  | { kind: 'tree'; data: TreeNode }
  | { kind: 'bullet'; data: BulletSeries }
  | { kind: 'kpis'; data: KPISeries }

export type AdapterParams = Record<string, any> & {
  since?: string | Date | number
  projectId?: string
  repoShort?: string
}

export type AdapterSupport = { ok: true } | { ok: false; reason: string }

export interface DatasetAdapter {
  defaultType: ChartType
  availableTypes?: ChartType[]
  fetcher: (params: AdapterParams, signal?: AbortSignal) => Promise<any>
  toSeriesFor: (type: ChartType, raw: any, params: AdapterParams) => AnySeries
  isSupported: (type: ChartType, raw: any, params: AdapterParams) => AdapterSupport
  csv: (raw: any, series: AnySeries, params: AdapterParams) => string
}

export type ChartCommonProps = {
  ariaLabel: string
  height?: number
  className?: string
  style?: CSSProperties
}
