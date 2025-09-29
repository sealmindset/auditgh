import React from 'react'

export default function Loading() {
  return (
    <div className="animate-pulse text-sm text-slate-500" role="status" aria-live="polite">
      <div className="h-6 bg-slate-200 rounded mb-2" />
      <div className="h-48 bg-slate-100 rounded" />
      <span className="sr-only">Loading...</span>
    </div>
  )
}
