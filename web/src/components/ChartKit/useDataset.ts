import React from 'react'
import type { AdapterParams } from './types'

const cache = new Map<string, { t: number; data: any }>()
const DEFAULT_TTL = 60_000

export default function useDataset(
  fetcher: (params: AdapterParams, signal?: AbortSignal) => Promise<any>,
  params: AdapterParams,
  options?: { cacheTTL?: number }
) {
  const [data, setData] = React.useState<any>(null)
  const [loading, setLoading] = React.useState<boolean>(true)
  const [error, setError] = React.useState<any>(null)

  const cacheKey = React.useMemo(() => JSON.stringify(params || {}), [params])

  const doFetch = React.useCallback(async (signal?: AbortSignal) => {
    setLoading(true)
    setError(null)
    try {
      const ttl = options?.cacheTTL ?? DEFAULT_TTL
      const now = Date.now()
      const hit = cache.get(cacheKey)
      if (hit && (now - hit.t) < ttl) {
        setData(hit.data)
        setLoading(false)
        return
      }
      const d = await fetcher(params, signal)
      cache.set(cacheKey, { t: now, data: d })
      setData(d)
    } catch (e) {
      // ignore AbortError
      if ((e as any)?.name === 'AbortError') return
      setError(e)
    } finally {
      setLoading(false)
    }
  }, [fetcher, params, options?.cacheTTL, cacheKey])

  React.useEffect(() => {
    const ctrl = new AbortController()
    // eslint-disable-next-line @typescript-eslint/no-floating-promises
    doFetch(ctrl.signal)
    return () => ctrl.abort()
  }, [doFetch])

  const refresh = React.useCallback(() => {
    const ctrl = new AbortController()
    // Bust cache for this key
    cache.delete(cacheKey)
    // eslint-disable-next-line @typescript-eslint/no-floating-promises
    doFetch(ctrl.signal)
  }, [cacheKey, doFetch])

  return { data, loading, error, refresh }
}
