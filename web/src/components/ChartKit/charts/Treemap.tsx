import React from 'react'
import { ResponsiveTreeMap } from '@nivo/treemap'
import type { ChartCommonProps, TreeNode } from '../types'

export default function TreemapChart({ data, ariaLabel, height = 320, className }: ChartCommonProps & { data: TreeNode }) {
  return (
    <div className={className} style={{ height }} aria-label={ariaLabel}>
      <ResponsiveTreeMap
        data={data as any}
        identity="name"
        value="value"
        margin={{ top: 10, right: 10, bottom: 10, left: 10 }}
        labelSkipSize={14}
        labelTextColor={{ from: 'color', modifiers: [['darker', 1.2]] }}
        colors={{ scheme: 'set2' }}
        borderColor={{ from: 'color', modifiers: [['darker', 0.3]] }}
        animate
        role="img"
      />
    </div>
  )
}
