import React from 'react'
import { ResponsiveBullet } from '@nivo/bullet'
import type { BulletSeries, ChartCommonProps } from '../types'

export default function BulletChart({ data, ariaLabel, height = 160, className }: ChartCommonProps & { data: BulletSeries }) {
  return (
    <div className={className} style={{ height }} aria-label={ariaLabel}>
      <ResponsiveBullet
        data={data as any}
        margin={{ top: 10, right: 30, bottom: 20, left: 60 }}
        spacing={40}
        titleAlign="start"
        titleOffsetX={-40}
        measureSize={0.5}
        role="img"
      />
    </div>
  )
}
