import type { PieSeries, TreeNode } from '../types'

export const SEVERITY_ORDER = ['Critical','High','Medium','Low','Info','Unknown'] as const
export type Severity = typeof SEVERITY_ORDER[number]

export function normalizeSeverity(s: any): Severity {
  const v = String(s || '').trim().toLowerCase()
  if (v.startsWith('crit')) return 'Critical'
  if (v.startsWith('hi')) return 'High'
  if (v.startsWith('med')) return 'Medium'
  if (v.startsWith('lo')) return 'Low'
  if (v.startsWith('in')) return 'Info'
  return 'Unknown'
}

export function countsToPie(counts: Record<string, number>): PieSeries {
  return Object.entries(counts).map(([k, v]) => ({ id: k, label: k, value: v }))
}

export function pieToTreeRoot(name: string, pie: PieSeries): TreeNode {
  return { name, children: pie.map(d => ({ name: String(d.id), value: d.value })) }
}

export function bucketByDay<T>(rows: T[], getDate: (r: T) => Date | null): Map<string, number> {
  const map = new Map<string, number>()
  for (const r of rows || []) {
    const d = getDate(r)
    if (!d || isNaN(d.getTime())) continue
    const key = d.toISOString().slice(0,10)
    map.set(key, (map.get(key) || 0) + 1)
  }
  return map
}

export function mapToLineSeries(name: string, m: Map<string, number>) {
  const entries = Array.from(m.entries()).sort(([a],[b]) => a.localeCompare(b))
  return [{ id: name, data: entries.map(([x,y]) => ({ x, y })) }]
}
