import React from 'react'
import type { ChartCommonProps, KPISeries } from '../types'

export default function KPIs({ data, ariaLabel, className }: ChartCommonProps & { data: KPISeries }) {
  return (
    <div className={className} aria-label={ariaLabel}>
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        {data.map((kpi, idx) => (
          <div key={idx} className={`rounded border p-3 ${kpi.colorClass || 'bg-white'}`}>
            <div className="text-xs text-slate-500">{kpi.label}</div>
            <div className="text-xl font-semibold">{Number(kpi.value || 0).toLocaleString()}</div>
            {kpi.sublabel ? <div className="text-xs text-slate-500">{kpi.sublabel}</div> : null}
          </div>
        ))}
      </div>
    </div>
  )
}
