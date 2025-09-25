import React, { useMemo, useState } from 'react'

export type ColumnDef<T> = {
  key: keyof T | string
  header: string
  sortable?: boolean
  widthClass?: string
  render?: (row: T) => React.ReactNode
  filter?: {
    type: 'enum' | 'text'
    getValue?: (row: T) => string
    disabled?: boolean
    enumValues?: string[]
    showInHeader?: boolean
  }
}

export type DataTableProps<T> = {
  data: T[]
  columns: ColumnDef<T>[]
  pageSizeOptions?: number[]
  defaultPageSize?: number
  searchPlaceholder?: string
  filterKeys?: (keyof T | string)[]
  rowClassName?: (row: T, idx: number) => string
  // Optional: provide external enum filter state keyed by column key and a callback to sync changes.
  externalEnumFilters?: Record<string, string[] | undefined>
  onExternalEnumFiltersChange?: (next: Record<string, string[] | undefined>) => void
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
  externalEnumFilters,
  onExternalEnumFiltersChange,
}: DataTableProps<T>) {
  const [query, setQuery] = useState('')
  const [pageSize, setPageSize] = useState(defaultPageSize)
  const [page, setPage] = useState(1)
  const [sortKey, setSortKey] = useState<string | null>(null)
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('asc')
  // Column filters (applied)
  const [filters, setFilters] = useState<Record<string, { type: 'enum' | 'text'; selected?: string[]; query?: string }>>({})
  // Open filter menu state
  const [openMenuKey, setOpenMenuKey] = useState<string | null>(null)
  const [menuPos, setMenuPos] = useState<{ top: number; left: number; width: number } | null>(null)
  const [menuSearch, setMenuSearch] = useState<string>('') // enum list search
  const [menuDraftSelected, setMenuDraftSelected] = useState<string[]>([])
  const [menuDraftQuery, setMenuDraftQuery] = useState<string>('')

  function colKey(c: ColumnDef<T>): string { return String(c.key) }
  function getValue(c: ColumnDef<T>, row: T): string {
    const raw = c.filter?.getValue ? c.filter.getValue(row) : (row[c.key as keyof T] as any)
    return String(raw ?? '')
  }

  function getEnumSelForKey(k: string): string[] | undefined {
    if (externalEnumFilters && Object.prototype.hasOwnProperty.call(externalEnumFilters, k)) {
      return externalEnumFilters[k]
    }
    const f = filters[k]
    if (f && f.type === 'enum') return f.selected
    return undefined
  }

  const normalizedFilterKeys = useMemo(() => {
    if (filterKeys && filterKeys.length > 0) return filterKeys
    // default to all string-like keys from first row
    const first = data[0]
    return first ? (Object.keys(first) as (keyof T | string)[]) : []
  }, [data, filterKeys])

  // Build unique enum values per column (limited to 200 to keep the menu snappy)
  const enumValuesMap = useMemo(() => {
    const m = new Map<string, string[]>()
    columns.forEach((c) => {
      const k = colKey(c)
      if (c.filter?.type !== 'enum' || c.filter?.disabled) return
      const baseVals = c.filter?.enumValues
      if (baseVals && baseVals.length) {
        m.set(k, Array.from(new Set(baseVals.map(v => String(v)))) )
        return
      }
      const set = new Set<string>()
      for (const row of data) {
        set.add(getValue(c, row))
        if (set.size >= 5000) break // hard cap collection if data is huge
      }
      const arr = Array.from(set)
      arr.sort((a, b) => a.toLowerCase().localeCompare(b.toLowerCase()))
      m.set(k, arr.slice(0, 200))
    })
    return m
  }, [columns, data])

  // Apply column filters first, then global search
  const baseAfterColumnFilters = useMemo(() => {
    const haveAny = Object.keys(filters).length > 0
    // If using external enum filters only, we still consider filters active
    const usingExternal = externalEnumFilters && Object.keys(externalEnumFilters).length > 0
    if (!haveAny && !usingExternal) return data
    return data.filter((row) => {
      for (const c of columns) {
        const k = colKey(c)
        const f = filters[k]
        if (!f || c.filter?.disabled) {
          // Even if internal filter is missing, external enum filters may exist
          const extSel = getEnumSelForKey(k)
          if (extSel !== undefined && c.filter?.type === 'enum') {
            const val = getValue(c, row)
            if (extSel.length === 0) return false
            if (!extSel.includes(val)) return false
          }
          continue
        }
        const val = getValue(c, row)
        if (f.type === 'enum') {
          const sel = getEnumSelForKey(k)
          if (sel !== undefined) {
            if (sel.length === 0) return false
            if (!sel.includes(val)) return false
          }
        } else if (f.type === 'text') {
          const q = (f.query || '').trim().toLowerCase()
          if (q && !val.toLowerCase().includes(q)) return false
        }
      }
      return true
    })
  }, [data, columns, filters, externalEnumFilters])

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase()
    if (!q) return baseAfterColumnFilters
    return baseAfterColumnFilters.filter((row) =>
      normalizedFilterKeys.some((k) => String((row as any)[k] ?? '').toLowerCase().includes(q))
    )
  }, [baseAfterColumnFilters, query, normalizedFilterKeys])

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

  function isFilterActiveFor(key: string): boolean {
    const enumSel = getEnumSelForKey(key)
    if (enumSel !== undefined) return true
    const f = filters[key]
    if (!f) return false
    if (f.type === 'text') return !!(f.query && f.query.trim())
    return false
  }

  function openMenu(k: string, c: ColumnDef<T>, anchorEl?: HTMLElement) {
    if (c.filter?.disabled) return
    setOpenMenuKey(k)
    setMenuSearch('')
    // Anchor menu to the trigger button using viewport coordinates
    if (anchorEl) {
      const rect = anchorEl.getBoundingClientRect()
      const menuWidth = 256 // w-64
      const menuHeight = 320 // max-h-80 (20rem)
      const margin = 4
      let left = rect.left
      let top = rect.bottom + margin
      // Flip above if bottom would be clipped
      if (top + menuHeight > window.innerHeight - 8) {
        top = Math.max(8, rect.top - margin - menuHeight)
      }
      // Keep within viewport horizontally
      left = Math.min(window.innerWidth - menuWidth - 8, Math.max(8, left))
      setMenuPos({ top, left, width: menuWidth })
    } else {
      setMenuPos(null)
    }
    const current = filters[k]
    if (c.filter?.type === 'enum') {
      // Default to all values selected if no active filter
      const all = enumValuesMap.get(k) || []
      const sel = getEnumSelForKey(k)
      setMenuDraftSelected(sel !== undefined ? [...(sel || [])] : [...all])
      setMenuDraftQuery('')
    } else if (c.filter?.type === 'text') {
      setMenuDraftQuery(current?.query || '')
      setMenuDraftSelected([])
    }
  }

  function applyMenu(k: string, c: ColumnDef<T>) {
    setFilters((prev) => {
      const next = { ...prev }
      if (c.filter?.type === 'enum') {
        const all = enumValuesMap.get(k) || []
        const sel = [...menuDraftSelected]
        if (onExternalEnumFiltersChange) {
          const curr = { ...(externalEnumFilters || {}) }
          curr[k] = sel.length === all.length ? undefined : sel
          onExternalEnumFiltersChange(curr)
        } else {
          // Treat full selection as no filter (remove entry).
          if (sel.length === all.length) delete next[k]
          else next[k] = { type: 'enum', selected: sel }
        }
      } else if (c.filter?.type === 'text') {
        const q = (menuDraftQuery || '').trim()
        if (!q) delete next[k]
        else next[k] = { type: 'text', query: q }
      }
      return next
    })
    setOpenMenuKey(null)
    setMenuPos(null)
  }

  function clearMenu(k: string) {
    setFilters((prev) => {
      const next = { ...prev }
      delete next[k]
      if (onExternalEnumFiltersChange && externalEnumFilters) {
        const curr = { ...(externalEnumFilters) }
        delete curr[k]
        onExternalEnumFiltersChange(curr)
      }
      return next
    })
    // Reset menu draft to all enum values selected (visual reset) when clearing
    const all = enumValuesMap.get(k) || []
    setMenuDraftSelected([...all])
    setOpenMenuKey(null)
    setMenuPos(null)
  }

  function setEnumFilterFromSelection(k: string, c: ColumnDef<T>, sel: string[]) {
    const all = enumValuesMap.get(k) || []
    if (onExternalEnumFiltersChange) {
      const curr = { ...(externalEnumFilters || {}) }
      curr[k] = sel.length === all.length ? undefined : [...sel]
      onExternalEnumFiltersChange(curr)
      return
    }
    setFilters((prev) => {
      const next = { ...prev }
      // Full selection => no filter entry
      if (sel.length === all.length) {
        delete next[k]
      } else {
        // Set active filter (even if sel is empty: means zero-match)
        next[k] = { type: 'enum', selected: [...sel] }
      }
      return next
    })
  }

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
                    className={`text-left px-3 py-2 font-medium relative ${c.widthClass || ''} ${canSort ? 'cursor-pointer select-none' : ''}`}
                    onClick={() => (canSort ? toggleSort(k) : undefined)}
                  >
                    <div className="flex items-center gap-1">
                      <span>{c.header}</span>
                      {canSort && (
                        <span className="text-xs text-slate-500">
                          {isSorted ? (sortDir === 'asc' ? '▲' : '▼') : '⇅'}
                        </span>
                      )}
                      {c.filter && c.filter.showInHeader !== false && !c.filter.disabled && (
                        <button
                          type="button"
                          className={`ml-1 text-xs px-1 py-0.5 border rounded ${isFilterActiveFor(k) ? 'bg-slate-300' : 'bg-slate-100'} hover:bg-slate-200`}
                          onClick={(e) => { e.stopPropagation(); openMenu(k, c, e.currentTarget as HTMLElement) }}
                          title="Filter"
                        >
                          ⚲
                        </button>
                      )}
                    </div>
                    {openMenuKey === k && c.filter && c.filter.showInHeader !== false && !c.filter.disabled && (
                      <>
                        {/* overlay to close on outside click */}
                        <div className="fixed inset-0 z-40" onClick={() => { setOpenMenuKey(null); setMenuPos(null) }} />
                        <div className="fixed z-50" style={{ top: (menuPos?.top ?? 0), left: (menuPos?.left ?? 0) }}>
                          <div className="relative bg-white border rounded shadow-lg p-3 w-64 max-h-80 overflow-auto">
                          {c.filter.type === 'enum' ? (
                            <div className="space-y-2" onClick={(e)=>e.stopPropagation()}>
                              <input
                                className="w-full border rounded px-2 py-1 text-sm"
                                placeholder="Search values…"
                                value={menuSearch}
                                onChange={(e)=>setMenuSearch(e.target.value)}
                              />
                              <div className="text-xs text-slate-600 flex items-center gap-2 mb-1">
                                <input type="checkbox" checked={(enumValuesMap.get(k)?.length||0) > 0 && (menuDraftSelected.length === (enumValuesMap.get(k)?.filter(v => v.toLowerCase().includes(menuSearch.trim().toLowerCase())).length || 0))}
                                  onChange={(e)=>{
                                    const list = (enumValuesMap.get(k) || []).filter(v => v.toLowerCase().includes(menuSearch.trim().toLowerCase()))
                                    const nextSel = e.target.checked ? [...list] : []
                                    setMenuDraftSelected(nextSel)
                                    setEnumFilterFromSelection(k, c, nextSel)
                                  }}
                                />
                                <span>Select All</span>
                              </div>
                              <div className="max-h-52 overflow-auto border rounded">
                                {(enumValuesMap.get(k) || [])
                                  .filter(v => v.toLowerCase().includes(menuSearch.trim().toLowerCase()))
                                  .map(v => (
                                    <label key={v} className="flex items-center gap-2 px-2 py-1 text-sm border-b last:border-b-0">
                                      <input type="checkbox" checked={menuDraftSelected.includes(v)} onChange={(e)=>{
                                        setMenuDraftSelected(prev => {
                                          const next = e.target.checked ? Array.from(new Set([...prev, v])) : prev.filter(x => x!==v)
                                          setEnumFilterFromSelection(k, c, next)
                                          return next
                                        })
                                      }} />
                                      <span className="truncate" title={v}>{v || '—'}</span>
                                    </label>
                                  ))}
                              </div>
                              <div className="flex items-center justify-end gap-2 pt-2">
                                <button className="px-2 py-1 text-sm bg-slate-100 rounded" onClick={(e)=>{e.stopPropagation(); clearMenu(k)}}>Clear</button>
                                <button className="px-2 py-1 text-sm bg-blue-600 text-white rounded" onClick={(e)=>{e.stopPropagation(); applyMenu(k, c)}}>Apply</button>
                              </div>
                            </div>
                          ) : (
                            <div className="space-y-2" onClick={(e)=>e.stopPropagation()}>
                              <input
                                className="w-full border rounded px-2 py-1 text-sm"
                                placeholder="Contains…"
                                value={menuDraftQuery}
                                onChange={(e)=>setMenuDraftQuery(e.target.value)}
                              />
                              <div className="flex items-center justify-end gap-2 pt-2">
                                <button className="px-2 py-1 text-sm bg-slate-100 rounded" onClick={(e)=>{e.stopPropagation(); clearMenu(k)}}>Clear</button>
                                <button className="px-2 py-1 text-sm bg-blue-600 text-white rounded" onClick={(e)=>{e.stopPropagation(); applyMenu(k, c)}}>Apply</button>
                              </div>
                            </div>
                          )}
                          </div>
                        </div>
                      </>
                    )}
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
