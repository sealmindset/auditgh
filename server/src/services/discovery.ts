import { logger } from '../config/logging.js'

export type DiscoveredRef = {
  url: string
  title?: string
  source_type: 'kev' | 'epss' | 'osv' | 'nvd' | 'snyk' | 'github_repo' | 'github_code' | 'article' | 'blog' | 'exploit_db' | 'metasploit' | 'other'
  reason?: string
  score?: number
}

export type QueryLog = { source: string; query: string; status: 'ok'|'error'; count: number; error?: string }

export type DiscoveryInput = {
  target: 'terraform' | 'oss' | 'codeql' | 'secret' | 'cicd'
  context: Record<string, any>
  max?: number
}

const memCache = new Map<string, { ts: number, refs: DiscoveredRef[], logs: QueryLog[] }>()
const TEN_MIN = 10 * 60 * 1000

async function safeJson<T=any>(resp: any): Promise<T|null> {
  try { return await resp.json() as any } catch { return null }
}

function isCve(s: string): boolean { return /^CVE-\d{4}-\d{4,}$/i.test(s) }
function isGhsa(s: string): boolean { return /^GHSA-/i.test(s) }

function extractIdsFromContext(target: DiscoveryInput['target'], ctx: Record<string, any>): { cve?: string, ghsa?: string, rule?: string, cwe?: string, package?: string, version?: string } {
  const out: any = {}
  const tryStr = (v: any) => (v==null? '': String(v))
  if (target === 'oss') {
    const vid = tryStr(ctx.vuln_id || ctx.cve || ctx.ghsa)
    if (isCve(vid)) out.cve = vid.toUpperCase()
    if (isGhsa(vid)) out.ghsa = vid.toUpperCase()
    out.package = tryStr(ctx.package)
    out.version = tryStr(ctx.version)
  } else if (target === 'codeql') {
    const rid = tryStr(ctx.rule_id)
    if (rid) out.rule = rid
    const msg = tryStr(ctx.message)
    const cweMatch = /(CWE-\d{1,4})/i.exec(msg)
    if (cweMatch) out.cwe = cweMatch[1].toUpperCase()
  } else if (target === 'terraform') {
    const rid = tryStr(ctx.rule_id)
    if (rid) out.rule = rid
  } else if (target === 'secret') {
    const rid = tryStr(ctx.detector || ctx.rule_id)
    if (rid) out.rule = rid
  }
  return out
}

function scoreRef(u: string, title?: string): { type: DiscoveredRef['source_type'], score: number, reason: string } {
  const url = u.toLowerCase()
  const t = (title || '').toLowerCase()
  const hasPoC = url.includes('poc') || url.includes('proof') || t.includes('poc') || t.includes('proof') || url.includes('exploit') || t.includes('exploit')
  if (url.includes('cisa.gov/known-exploited-vulnerabilities') || url.includes('/kev/')) return { type: 'kev', score: 100, reason: 'Listed in CISA KEV' }
  if (url.includes('exploit-db.com')) return { type: 'exploit_db', score: hasPoC ? 95 : 80, reason: 'Exploit-DB reference' }
  if (url.includes('rapid7') || url.includes('metasploit')) return { type: 'metasploit', score: hasPoC ? 95 : 80, reason: 'Metasploit/Rapid7 reference' }
  if (url.includes('nvd.nist.gov')) return { type: 'nvd', score: hasPoC ? 70 : 60, reason: 'NVD reference' }
  if (url.includes('snyk.io')) return { type: 'snyk', score: hasPoC ? 75 : 65, reason: 'Snyk advisory' }
  if (url.includes('github.com')) {
    const isCode = /github.com\/.+\/.+\/blob\//.test(url)
    const reason = hasPoC ? 'GitHub PoC/exploit' : 'GitHub reference'
    return { type: isCode ? 'github_code' : 'github_repo', score: hasPoC ? 85 : 70, reason }
  }
  if (url.includes('osv.dev')) return { type: 'osv', score: hasPoC ? 72 : 62, reason: 'OSV advisory' }
  if (url.includes('nist.gov')) return { type: 'nvd', score: 60, reason: 'NIST reference' }
  return { type: (hasPoC ? 'article' : 'other'), score: hasPoC ? 60 : 40, reason: hasPoC ? 'Mentions PoC/exploit' : 'General reference' }
}

function uniqUrls(items: DiscoveredRef[]): DiscoveredRef[] {
  const seen = new Set<string>()
  const out: DiscoveredRef[] = []
  for (const r of items) {
    const k = r.url.replace(/^http:\/\//,'https://').toLowerCase()
    if (seen.has(k)) continue
    seen.add(k)
    out.push(r)
  }
  return out
}

export async function discoverForContext(input: DiscoveryInput): Promise<{ references: DiscoveredRef[], queries: QueryLog[] }> {
  const key = JSON.stringify({ t: input.target, c: input.context, m: input.max })
  const now = Date.now()
  const cached = memCache.get(key)
  if (cached && (now - cached.ts) < TEN_MIN) return { references: cached.refs, queries: cached.logs }

  const logs: QueryLog[] = []
  const refs: DiscoveredRef[] = []
  const ids = extractIdsFromContext(input.target, input.context)
  const max = Math.max(1, Math.min(input.max || 10, 20))

  async function withLog<T>(source: string, query: string, fn: () => Promise<T[]>): Promise<void> {
    try {
      const arr = await fn()
      refs.push(...(arr as any))
      logs.push({ source, query, status: 'ok', count: (arr as any).length })
    } catch (e: any) {
      logger.warn({ source, query, e: String(e?.message || e) }, 'discovery query failed')
      logs.push({ source, query, status: 'error', count: 0, error: String(e?.message || e) })
    }
  }

  // OSV
  if (ids.cve || ids.ghsa || (ids.package && ids.version)) {
    await withLog('osv', ids.cve || ids.ghsa || `${ids.package}@${ids.version}`, async () => {
      let url = ''
      let json: any = null
      if (ids.cve || ids.ghsa) {
        const id = (ids.cve || ids.ghsa) as string
        url = `https://api.osv.dev/v1/vulns/${encodeURIComponent(id)}`
        json = await fetch(url).then(safeJson)
      } else {
        url = `https://api.osv.dev/v1/query`
        json = await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ package: { name: ids.package }, version: ids.version }) }).then(safeJson)
      }
      const out: DiscoveredRef[] = []
      const refs1 = (json?.references || json?.vulns?.[0]?.references || []) as any[]
      for (const r of refs1) {
        const u = String(r?.url || '')
        if (!u) continue
        const sc = scoreRef(u)
        out.push({ url: u, source_type: sc.type, reason: sc.reason, score: sc.score })
      }
      return out
    })
  }

  // KEV (CISA)
  if (ids.cve) {
    await withLog('kev', ids.cve, async () => {
      const u = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
      const json: any = await fetch(u).then(safeJson)
      const items = (json?.vulnerabilities || []) as any[]
      const found = items.find((v) => String(v?.cveID || '').toUpperCase() === ids.cve)
      if (!found) return []
      const link = 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog'
      return [{ url: link, source_type: 'kev', reason: 'Listed in CISA KEV', score: 100 }]
    })
  }

  // EPSS
  if (ids.cve) {
    await withLog('epss', ids.cve, async () => {
      const u = `https://api.first.org/data/v1/epss?cve=${encodeURIComponent(ids.cve!)}`
      const json: any = await fetch(u).then(safeJson)
      const d = Array.isArray(json?.data) ? json.data[0] : null
      if (!d) return []
      const link = `https://api.first.org/data/v1/epss?cve=${encodeURIComponent(ids.cve!)}`
      return [{ url: link, source_type: 'epss', reason: `EPSS score ${d.epss} percentile ${d.percentile}`, score: 50 }]
    })
  }

  // GitHub search (repos + code)
  if (ids.cve || ids.ghsa || ids.rule) {
    const token = process.env.GITHUB_TOKEN || process.env.GH_TOKEN || ''
    const qBase = ids.cve || ids.ghsa || ids.rule || ''
    const qRepo = `${qBase} poc OR exploit in:name,description,readme`
    const qCode = `${qBase} poc OR exploit in:file`
    const headers: any = token ? { Authorization: `Bearer ${token}`, Accept: 'application/vnd.github+json' } : { Accept: 'application/vnd.github+json' }
    await withLog('github_repos', qRepo, async () => {
      const u = `https://api.github.com/search/repositories?q=${encodeURIComponent(qRepo)}&sort=stars&order=desc&per_page=5`
      const json: any = await fetch(u, { headers }).then(safeJson)
      const items = (json?.items || []) as any[]
      return items.map(it => ({ url: it?.html_url, title: it?.full_name, source_type: 'github_repo', reason: 'GitHub repo search', score: Math.min(90, 60 + (it?.stargazers_count || 0) / 50) }))
    })
    await withLog('github_code', qCode, async () => {
      const u = `https://api.github.com/search/code?q=${encodeURIComponent(qCode)}&per_page=5`
      const json: any = await fetch(u, { headers }).then(safeJson)
      const items = (json?.items || []) as any[]
      return items.map(it => ({ url: it?.html_url, title: it?.name, source_type: 'github_code', reason: 'GitHub code search', score: 75 }))
    })
  }

  // DuckDuckGo fallback
  {
    const q = [ids.cve || ids.ghsa || ids.rule, 'exploit poc'].filter(Boolean).join(' ')
    if (q) await withLog('ddg', q, async () => {
      const u = `https://duckduckgo.com/html/?q=${encodeURIComponent(q)}`
      const html = await fetch(u).then(r => r.text())
      const out: DiscoveredRef[] = []
      const re = /<a[^>]+class=\"result__a\"[^>]+href=\"([^\"]+)\"[^>]*>(.*?)<\/a>/gi
      let m: RegExpExecArray | null
      while ((m = re.exec(html)) && out.length < 8) {
        const href = m[1]
        const title = m[2]?.replace(/<[^>]+>/g, '')
        if (!href || href.includes('duckduckgo.com')) continue
        const sc = scoreRef(href, title)
        out.push({ url: href, title, source_type: sc.type, reason: sc.reason, score: sc.score })
      }
      return out
    })
  }

  const ranked = uniqUrls(refs).sort((a,b) => (b.score || 0) - (a.score || 0)).slice(0, max)
  memCache.set(key, { ts: now, refs: ranked, logs })
  return { references: ranked, queries: logs }
}

export function credibleExploitFound(refs: DiscoveredRef[]): boolean {
  const hasKev = refs.some(r => r.source_type === 'kev')
  if (hasKev) return true
  const hasStrong = refs.some(r => ['exploit_db','metasploit'].includes(r.source_type))
  if (hasStrong) return true
  const ghPoC = refs.filter(r => (r.source_type === 'github_repo' || r.source_type === 'github_code') && /poc|exploit/i.test(`${r.title||''} ${r.url}`))
  if (ghPoC.length >= 2) return true
  return false
}
