import React from 'react'

export default function Empty({ message }: { message?: string }) {
  return (
    <div className="text-sm text-slate-600" role="status" aria-live="polite">
      <div className="flex items-center gap-2">
        <span>ⓘ</span>
        <span>{message || 'No data available.'}</span>
      </div>
    </div>
  )
}
