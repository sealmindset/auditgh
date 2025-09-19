import React, { useMemo, useState } from 'react'

export type ColumnDef<T> = {
  key: keyof T | string
  header: string
  sortable?: boolean
  widthClass?: string
  render?: (row: T) => React.ReactNode
}

export type DataTableProps<T> = {
  data: T[]
  columns: ColumnDef<T>[]
  pageSizeOptions?: number[]
  defaultPageSize?: number
  searchPlaceholder?: string
  filterKeys?: (keyof T | string)[]
  rowClassName?: (row: T, idx: number) => string
}

function compareValues(a: any, b: any): number {
  // Normalize undefined/null
  const av = a ?? ''
  const bv = b ?? ''
  // Try date strings
  const aDate = typeof av === 'string' && /\d{4}-\d{2}-\d{2}T/.test(av) ? Date.parse(av) : NaN
  const bDate = typeof bv === 'string' && /\d{4}-\d{2}-\d{2}T/.test(bv) ? Date.parse(bv) : NaN
  if (!isNaN(aDate) && !isNaN(bDate)) return aDate - bDate
  // Numbers
  if (typeof av === 'number' && typeof bv === 'number') return av - bv
  // String compare, case-insensitive
  return String(av).toLowerCase().localeCompare(String(bv).toLowerCase())
}

export default function DataTable<T extends Record<string, any>>({
  data,
  columns,
  pageSizeOptions = [10, 25, 50],
  defaultPageSize = 10,
  searchPlaceholder = 'Search…',
  filterKeys,
  rowClassName,
}: DataTableProps<T>) {
  const [query, setQuery] = useState('')
  const [pageSize, setPageSize] = useState(defaultPageSize)
  const [page, setPage] = useState(1)
  const [sortKey, setSortKey] = useState<string | null>(null)
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('asc')

  const normalizedFilterKeys = useMemo(() => {
    if (filterKeys && filterKeys.length > 0) return filterKeys
    // default to all string-like keys from first row
    const first = data[0]
    return first ? (Object.keys(first) as (keyof T | string)[]) : []
  }, [data, filterKeys])

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase()
    if (!q) return data
    return data.filter((row) =>
      normalizedFilterKeys.some((k) => String((row as any)[k] ?? '').toLowerCase().includes(q))
    )
  }, [data, query, normalizedFilterKeys])

  const sorted = useMemo(() => {
    if (!sortKey) return filtered
    const arr = [...filtered]
    arr.sort((a, b) => {
      const res = compareValues((a as any)[sortKey], (b as any)[sortKey])
      return sortDir === 'asc' ? res : -res
    })
    return arr
  }, [filtered, sortKey, sortDir])

  const total = sorted.length
  const totalPages = Math.max(1, Math.ceil(total / pageSize))
  const pageSafe = Math.min(Math.max(1, page), totalPages)
  const startIdx = (pageSafe - 1) * pageSize
  const endIdx = Math.min(total, startIdx + pageSize)
  const pageRows = sorted.slice(startIdx, endIdx)

  function toggleSort(k: string) {
    if (sortKey !== k) {
      setSortKey(k)
      setSortDir('asc')
      return
    }
    setSortDir((d) => (d === 'asc' ? 'desc' : 'asc'))
  }

  function pageButton(num: number) {
    return (
      <button
        key={num}
        className={`border rounded px-2 py-1 text-sm ${num === pageSafe ? 'bg-slate-200' : ''}`}
        onClick={() => setPage(num)}
      >
        {num}
      </button>
    )
  }

  const pageButtons = useMemo(() => {
    const buttons: React.ReactNode[] = []
    const maxButtons = 5
    const half = Math.floor(maxButtons / 2)
    let start = Math.max(1, pageSafe - half)
    let end = Math.min(totalPages, start + maxButtons - 1)
    start = Math.max(1, Math.min(start, end - maxButtons + 1))
    for (let i = start; i <= end; i++) buttons.push(pageButton(i))
    return buttons
  }, [pageSafe, totalPages])

  return (
    <div className="rounded shadow-sm bg-white">
      <div className="flex items-center justify-between p-3 border-b">
        <label className="text-sm flex items-center gap-2">
          <span>Show</span>
          <select
            className="border rounded px-2 py-1"
            value={pageSize}
            onChange={(e) => {
              const ps = parseInt(e.target.value || '10', 10)
              setPageSize(ps)
              setPage(1)
            }}
          >
            {pageSizeOptions.map((opt) => (
              <option key={opt} value={opt}>
                {opt}
              </option>
            ))}
          </select>
          <span>entries</span>
        </label>
        <label className="text-sm flex items-center gap-2">
          <span>Search:</span>
          <input
            className="border rounded px-2 py-1"
            placeholder={searchPlaceholder}
            value={query}
            onChange={(e) => {
              setQuery(e.target.value)
              setPage(1)
            }}
          />
        </label>
      </div>
      <div className="overflow-x-auto">
        <table className="min-w-full text-sm">
          <thead className="bg-slate-100 text-slate-700">
            <tr>
              {columns.map((c) => {
                const k = String(c.key)
                const isSorted = sortKey === k
                const canSort = c.sortable !== false
                return (
                  <th
                    key={k}
                    className={`text-left px-3 py-2 font-medium ${c.widthClass || ''} ${canSort ? 'cursor-pointer select-none' : ''}`}
                    onClick={() => (canSort ? toggleSort(k) : undefined)}
                  >
                    <div className="flex items-center gap-1">
                      <span>{c.header}</span>
                      {canSort && (
                        <span className="text-xs text-slate-500">
                          {isSorted ? (sortDir === 'asc' ? '▲' : '▼') : '⇅'}
                        </span>
                      )}
                    </div>
                  </th>
                )
              })}
            </tr>
          </thead>
          <tbody>
            {pageRows.length === 0 ? (
              <tr>
                <td className="px-3 py-3 text-center text-slate-500" colSpan={columns.length}>
                  No results
                </td>
              </tr>
            ) : (
              pageRows.map((row, idx) => (
                <tr key={idx} className={`hover:bg-slate-50 ${rowClassName ? rowClassName(row, idx) : ''}`}>
                  {columns.map((c) => (
                    <td key={String(c.key)} className="px-3 py-2 align-top">
                      {c.render ? c.render(row) : String(row[c.key as keyof T] ?? '')}
                    </td>
                  ))}
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
      <div className="flex items-center justify-between p-3 border-t text-sm text-slate-600">
        <div>
          {total === 0
            ? 'Showing 0 entries'
            : `Showing ${startIdx + 1} to ${endIdx} of ${total} entries`}
        </div>
        <div className="flex items-center gap-2">
          <button
            className="border rounded px-2 py-1 text-sm disabled:opacity-50"
            onClick={() => setPage((p) => Math.max(1, p - 1))}
            disabled={pageSafe <= 1}
          >
            Previous
          </button>
          {pageButtons}
          <button
            className="border rounded px-2 py-1 text-sm disabled:opacity-50"
            onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
            disabled={pageSafe >= totalPages}
          >
            Next
          </button>
        </div>
      </div>
    </div>
  )
}
