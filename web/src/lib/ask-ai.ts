import { xhrPostJson } from './xhr'

export type AskAIContext = {
  overview?: any;
  visibleTables: Array<{ id: string; name: string; fields: any[]; rows: any[] }>;
  selection?: { tableId: string; rowIndexes: number[] } | null;
};

// Standalone Ask AI: calls existing backend /api/ai/assist (Express) with minimal defaults.
// We embed the free-form question into the context to avoid server changes.
export async function askAI(question: string, context: AskAIContext): Promise<string> {
  // lightweight telemetry (client-side only)
  try {
    const approxSize = JSON.stringify(context).length
    // eslint-disable-next-line no-console
    console.log(`[AskAI] q="${String(question).slice(0,80)}..." size=${approxSize} tables=${context.visibleTables?.length || 0}`)
  } catch { /* ignore */ }

  const body: any = {
    provider: 'ollama',
    // allow server default if model is unspecified
    target: 'cicd',
    project_id: context?.overview?.id || undefined,
    repo_short: undefined,
    context: { ...context, question },
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
