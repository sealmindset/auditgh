import React from 'react'

export default function ErrorState({ message, onRetry }: { message?: string; onRetry?: () => void }) {
  return (
    <div className="text-sm text-red-700" role="alert" aria-live="assertive">
      <div className="flex items-center justify-between">
        <span>{message || 'Failed to load data.'}</span>
        {onRetry ? (
          <button type="button" className="ml-3 px-2 py-1 border rounded bg-white hover:bg-slate-50" onClick={onRetry}>Retry</button>
        ) : null}
      </div>
    </div>
  )
}
