import React from 'react'
import { ResponsivePie, type PieSvgProps } from '@nivo/pie'
import type { ChartCommonProps, PieSeries } from '../types'

export default function Donut({ data, innerRadius = 0.6, ariaLabel, height = 300, className }: ChartCommonProps & { data: PieSeries; innerRadius?: number }) {
  return (
    <div className={className} style={{ height }} aria-label={ariaLabel}>
      <ResponsivePie
        data={data}
        margin={{ top: 10, right: 10, bottom: 10, left: 10 }}
        innerRadius={innerRadius}
        padAngle={0.7}
        cornerRadius={3}
        activeOuterRadiusOffset={8}
        colors={{ scheme: 'set2' }}
        borderColor={{ from: 'color', modifiers: [['darker', 0.2]] }}
        arcLinkLabelsSkipAngle={10}
        arcLinkLabelsTextColor="#475569"
        arcLinkLabelsThickness={1}
        arcLinkLabelsColor={{ from: 'color' }}
        arcLabelsSkipAngle={10}
        arcLabelsTextColor={{ from: 'color', modifiers: [['darker', 2]] }}
      />
    </div>
  )
}
