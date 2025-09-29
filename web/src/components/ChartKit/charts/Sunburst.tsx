import React from 'react'
import { ResponsiveSunburst } from '@nivo/sunburst'
import type { ChartCommonProps, TreeNode } from '../types'

export default function SunburstChart({ data, ariaLabel, height = 320, className }: ChartCommonProps & { data: TreeNode }) {
  return (
    <div className={className} style={{ height }} aria-label={ariaLabel}>
      <ResponsiveSunburst
        data={data as any}
        id="name"
        value="value"
        margin={{ top: 10, right: 10, bottom: 10, left: 10 }}
        cornerRadius={2}
        borderColor={{ from: 'color', modifiers: [['darker', 0.3]] }}
        colors={{ scheme: 'set2' }}
        animate
        role="img"
      />
    </div>
  )
}
