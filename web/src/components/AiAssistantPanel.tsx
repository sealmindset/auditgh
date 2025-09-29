import React, { useEffect, useMemo, useState } from 'react'
import { xhrGetJson, xhrPostJson } from '../lib/xhr'

export type AiTarget = 'terraform' | 'oss' | 'codeql' | 'secret' | 'cicd'

export default function AiAssistantPanel({
  target,
  projectId,
  repoShort,
  context,
  defaultProvider = 'ollama',
  onClose,
}: {
  target: AiTarget
  projectId?: string
  repoShort?: string | null
  context: Record<string, any>
  defaultProvider?: 'ollama' | 'openai'
  onClose?: () => void
}) {
  const [providers, setProviders] = useState<{ key: 'ollama'|'openai', models: string[] }[]>([])
  const [provider, setProvider] = useState<'ollama'|'openai'>(defaultProvider as any)
  const [model, setModel] = useState<string>('qwen2.5:3b')
  const [referenceUrls, setReferenceUrls] = useState<string>('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [responseText, setResponseText] = useState<string>('')
  const [analysisId, setAnalysisId] = useState<number | null>(null)
  const [autoDiscovery, setAutoDiscovery] = useState<boolean>(false)
  const [mode, setMode] = useState<'citations_only'|'analysis_with_citations'>('citations_only')
  const [applyExploit, setApplyExploit] = useState<boolean>(false)

  useEffect(() => {
    xhrGetJson('/api/ai/providers')
      .then((d) => {
        const provs = (d?.providers || []) as { key: 'ollama'|'openai', models: string[] }[]
        setProviders(provs)
        const defs = d?.defaults || {}
        const p = (defs.provider || provider) as 'ollama'|'openai'
        setProvider(p)
        const m = p === 'ollama' ? (defs.ollamaModel || 'qwen2.5:3b') : (defs.openaiModel || 'gpt-4o-mini')
        setModel(m)
      })
      .catch(() => {})
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  const contextPreview = useMemo(() => JSON.stringify(context, null, 2), [context])

  async function analyze() {
    setLoading(true)
    setError(null)
    setResponseText('')
    setAnalysisId(null)
    try {
      const urls = referenceUrls.split(/\s+/).map((s) => s.trim()).filter(Boolean)
      const body: any = {
        provider,
        model,
        target,
        project_id: projectId,
        repo_short: repoShort || undefined,
        context,
        reference_urls: urls,
        auto_discovery: autoDiscovery,
        mode,
        set_exploit_from_citations: applyExploit,
      }
      const data = await xhrPostJson('/api/ai/assist', body)
      const row = data?.data || {}
      setResponseText(String(row.response_text || ''))
      setAnalysisId(typeof row.id === 'number' ? row.id : null)
    } catch (e: any) {
      setError(e?.message || 'Analysis failed')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="border rounded p-3 bg-slate-50">
      <div className="flex items-center justify-between mb-2">
        <div className="font-medium text-sm">Ask AI</div>
        {onClose ? <button type="button" className="text-xs px-2 py-0.5 border rounded" onClick={onClose}>Close</button> : null}
      </div>
      <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-sm mb-3">
        <label className="flex flex-col">
          <span className="text-xs text-slate-600">Provider</span>
          <select className="border rounded px-2 py-1" value={provider} onChange={(e) => setProvider(e.target.value as any)}>
            <option value="ollama">Ollama</option>
            <option value="openai">OpenAI</option>
          </select>
        </label>
        <label className="flex flex-col">
          <span className="text-xs text-slate-600">Model</span>
          <input className="border rounded px-2 py-1" value={model} onChange={(e) => setModel(e.target.value)} placeholder={provider==='ollama' ? 'qwen2.5:3b' : 'gpt-4o-mini'} />
        </label>
        <label className="flex flex-col md:col-span-1">
          <span className="text-xs text-slate-600">Project / Repo</span>
          <input className="border rounded px-2 py-1" readOnly value={`${projectId || '—'} / ${repoShort || '—'}`} />
        </label>
      </div>
      <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-sm mb-3">
        <label className="flex items-center gap-2">
          <input type="checkbox" checked={autoDiscovery} onChange={(e)=>setAutoDiscovery(e.target.checked)} />
          <span>Auto-discover sources (Agent mode)</span>
        </label>
        <label className="flex flex-col">
          <span className="text-xs text-slate-600">Mode</span>
          <select className="border rounded px-2 py-1" value={mode} onChange={(e)=>setMode(e.target.value as any)}>
            <option value="citations_only">Citations only</option>
            <option value="analysis_with_citations">Analysis with citations</option>
          </select>
        </label>
        <label className="flex items-center gap-2">
          <input type="checkbox" checked={applyExploit} onChange={(e)=>setApplyExploit(e.target.checked)} />
          <span>Apply Exploit Available from citations</span>
        </label>
      </div>
      <label className="flex flex-col text-sm mb-3">
        <span className="text-xs text-slate-600">Reference URLs (space or newline separated)</span>
        <textarea className="border rounded px-2 py-1 min-h-[60px]" value={referenceUrls} onChange={(e) => setReferenceUrls(e.target.value)} placeholder="https://security.snyk.io/vuln/... https://nvd.nist.gov/vuln/detail/CVE-..." />
      </label>
      <details className="mb-3">
        <summary className="text-sm cursor-pointer text-slate-700">Prompt Context Preview</summary>
        <pre className="text-xs bg-white border rounded p-2 overflow-auto max-h-48 whitespace-pre-wrap">{contextPreview}</pre>
      </details>
      <div className="flex items-center gap-2 mb-2">
        <button type="button" className="px-3 py-1 bg-blue-600 text-white rounded disabled:opacity-50" onClick={analyze} disabled={loading}>{loading ? 'Analyzing…' : 'Analyze with AI'}</button>
        {typeof analysisId === 'number' ? <span className="text-xs text-slate-600">Saved analysis id: {analysisId}</span> : null}
      </div>
      {error ? <div className="text-xs text-red-700 mb-2">{error}</div> : null}
      <div className="text-sm">
        <div className="text-xs text-slate-600 mb-1">Response</div>
        <pre className="text-xs bg-white border rounded p-2 overflow-auto max-h-64 whitespace-pre-wrap">{responseText || '—'}</pre>
      </div>
    </div>
  )
}
