import React from 'react'
import { ResponsiveLine } from '@nivo/line'
import type { ChartCommonProps, LineSeries } from '../types'

export default function LineChart({ data, ariaLabel, height = 300, className }: ChartCommonProps & { data: LineSeries }) {
  return (
    <div className={className} style={{ height }} aria-label={ariaLabel}>
      <ResponsiveLine
        data={data as any}
        margin={{ top: 10, right: 20, bottom: 40, left: 50 }}
        xScale={{ type: 'point' }}
        yScale={{ type: 'linear', min: 'auto', max: 'auto', stacked: false, reverse: false }}
        axisBottom={{ orient: 'bottom', tickRotation: -30 }}
        axisLeft={{ orient: 'left' }}
        colors={{ scheme: 'set2' }}
        pointSize={4}
        pointBorderWidth={1}
        pointBorderColor={{ from: 'serieColor' }}
        useMesh
        enableSlices="x"
        role="img"
      />
    </div>
  )
}
