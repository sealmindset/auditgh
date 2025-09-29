import React from 'react'
import type { ChartType } from './types'

function storageKey(datasetKey: string) { return `chartkit.type:${datasetKey}` }

export default function ChartSwitch({
  datasetKey,
  types,
  value,
  onChange,
}: {
  datasetKey: string
  types: ChartType[]
  value?: ChartType
  onChange: (t: ChartType) => void
}) {
  const [selected, setSelected] = React.useState<ChartType | undefined>(() => {
    try {
      const v = localStorage.getItem(storageKey(datasetKey)) as ChartType | null
      return (v && types.includes(v)) ? v : value
    } catch { return value }
  })

  React.useEffect(() => {
    setSelected((prev) => {
      if (!prev || !types.includes(prev)) return value
      return prev
    })
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [datasetKey, types.join(','), value])

  function select(t: ChartType) {
    setSelected(t)
    try { localStorage.setItem(storageKey(datasetKey), t) } catch {}
    onChange(t)
  }

  return (
    <div className="inline-flex items-center gap-2">
      <label className="text-xs text-slate-600" htmlFor={`chart-type-${datasetKey}`}>Chart</label>
      <select
        id={`chart-type-${datasetKey}`}
        aria-label="Chart type"
        className="text-xs border rounded px-2 py-1 bg-white focus:outline-none focus:ring-2 focus:ring-blue-500"
        value={selected || value}
        onChange={(e) => select(e.target.value as ChartType)}
      >
        {types.map((t) => (
          <option key={t} value={t}>{t}</option>
        ))}
      </select>
    </div>
  )
}
