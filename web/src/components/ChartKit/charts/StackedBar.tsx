import React from 'react'
import { ResponsiveBar } from '@nivo/bar'
import type { BarSeries, ChartCommonProps } from '../types'

export default function StackedBarChart({ data, ariaLabel, height = 300, className }: ChartCommonProps & { data: BarSeries }) {
  const keys = data.keys
  return (
    <div className={className} style={{ height }} aria-label={ariaLabel}>
      <ResponsiveBar
        data={data.data}
        keys={keys}
        indexBy={data.indexBy}
        margin={{ top: 10, right: 10, bottom: 40, left: 50 }}
        padding={0.25}
        groupMode="stacked"
        valueScale={{ type: 'linear' }}
        indexScale={{ type: 'band', round: true }}
        colors={{ scheme: 'set2' }}
        borderColor={{ from: 'color', modifiers: [['darker', 1.6]] }}
        axisBottom={{ tickRotation: -30 }}
        labelSkipWidth={12}
        labelSkipHeight={12}
        labelTextColor={{ from: 'color', modifiers: [['darker', 1.6]] }}
        role="img"
      />
    </div>
  )
}
