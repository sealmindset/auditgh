import { xhrPostJson } from './xhr'

export type AskAIContext = {
  overview?: any;
  visibleTables: Array<{ id: string; name: string; fields: any[]; rows: any[] }>;
  selection?: { tableId: string; rowIndexes: number[] } | null;
};

function str(v: any): string {
  if (v == null) return ''
  if (typeof v === 'string') return v
  try { return JSON.stringify(v) } catch { return String(v) }
}

function clamp(s: string, max = 300): string {
  if (!s) return ''
  return s.length > max ? `${s.slice(0, max)}…` : s
}

function approxSize(obj: any): number {
  try { return JSON.stringify(obj).length } catch { return 0 }
}

function compactOverview(ov: any, maxFieldLen = 300): any {
  if (!ov || typeof ov !== 'object') return ov
  const out: any = {}
  for (const k of Object.keys(ov)) {
    const v = (ov as any)[k]
    if (typeof v === 'string') out[k] = clamp(v, maxFieldLen)
    else out[k] = v
  }
  return out
}

function pickRows(rows: any[], idxs?: number[], limit = 16): any[] {
  if (!Array.isArray(rows)) return []
  if (idxs && idxs.length) return idxs.map(i => rows[i]).filter(r => r != null)
  return rows.slice(0, Math.max(0, limit))
}

function compactRow(fields: any[] | undefined, row: any, maxFieldLen = 300): any {
  if (!row || typeof row !== 'object') return row
  const out: any = {}
  const keys = Array.isArray(fields) && fields.length
    ? fields.map((f: any) => (typeof f === 'string' ? f : f?.key)).filter(Boolean)
    : Object.keys(row)
  for (const k of keys) {
    const v = (row as any)[k]
    if (typeof v === 'string') out[k] = clamp(v, maxFieldLen)
    else if (typeof v === 'number' || typeof v === 'boolean' || v == null) out[k] = v
    else out[k] = clamp(str(v), maxFieldLen)
  }
  return out
}

function compactTable(tbl: { id: string; name: string; fields: any[]; rows: any[] }, selection: AskAIContext['selection'], opts: { maxRows: number; maxFieldLen: number }): any {
  const idxs = selection && selection.tableId === tbl.id ? (selection.rowIndexes || []) : undefined
  const rows = pickRows(tbl.rows || [], idxs, opts.maxRows).map(r => compactRow(tbl.fields, r, opts.maxFieldLen))
  return { id: tbl.id, name: clamp(tbl.name || '', 120), fields: tbl.fields, rows }
}

function compactContext(ctx: AskAIContext): AskAIContext {
  // Initial pass
  let maxRows = 16
  let maxFieldLen = 300
  let maxTables = 6
  let tables = (ctx.visibleTables || []).slice(0, maxTables)
  let out: AskAIContext = {
    overview: compactOverview(ctx.overview, maxFieldLen),
    visibleTables: tables.map(t => compactTable(t as any, ctx.selection || null, { maxRows, maxFieldLen })),
    selection: ctx.selection || null,
  }
  // If still large, progressively tighten
  const soft = 120_000
  if (approxSize(out) > soft) {
    maxRows = 8; maxFieldLen = 180; maxTables = 4
    tables = (ctx.visibleTables || []).slice(0, maxTables)
    out = {
      overview: compactOverview(ctx.overview, maxFieldLen),
      visibleTables: tables.map(t => compactTable(t as any, ctx.selection || null, { maxRows, maxFieldLen })),
      selection: ctx.selection || null,
    }
  }
  if (approxSize(out) > soft) {
    maxRows = 4; maxFieldLen = 120; maxTables = 3
    tables = (ctx.visibleTables || []).slice(0, maxTables)
    out = {
      overview: compactOverview(ctx.overview, maxFieldLen),
      visibleTables: tables.map(t => compactTable(t as any, ctx.selection || null, { maxRows, maxFieldLen })),
      selection: ctx.selection || null,
    }
  }
  return out
}

// Standalone Ask AI: calls existing backend /api/ai/assist (Express) with minimal defaults.
// We embed the free-form question into the context to avoid server changes.
export async function askAI(question: string, context: AskAIContext): Promise<string> {
  // telemetry
  let before = 0, after = 0
  try { before = approxSize(context) } catch { /* ignore */ }
  const slim = compactContext(context)
  try { after = approxSize(slim) } catch { /* ignore */ }
  // eslint-disable-next-line no-console
  try { console.log(`[AskAI] q="${String(question).slice(0,80)}..." ctx=${before}B→${after}B tables=${slim.visibleTables?.length || 0}`) } catch { /* ignore */ }

  const body: any = {
    provider: 'ollama',
    // allow server default if model is unspecified
    target: 'cicd',
    project_id: slim?.overview?.id || undefined,
    repo_short: undefined,
    context: { ...slim, question },
    reference_urls: [],
    auto_discovery: false,
    mode: 'analysis_with_citations',
    set_exploit_from_citations: false,
  }
  try {
    const resp = await xhrPostJson('/api/ai/assist', body)
    const row = resp?.data || {}
    return String(row.response_text || '')
  } catch (e: any) {
    return String(e?.message || 'Ask AI failed')
  }
}
