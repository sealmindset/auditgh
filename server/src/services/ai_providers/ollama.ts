import { logger } from '../../config/logging.js'

export type ChatMessage = { role: 'system' | 'user' | 'assistant', content: string }

export async function callOllamaChat(opts: { baseUrl?: string, model?: string, messages: ChatMessage[] }): Promise<{ text: string, durationMs: number }> {
  const baseUrl = (opts.baseUrl || process.env.OLLAMA_BASE_URL || 'http://ollama:11434').replace(/\/$/, '')
  const model = opts.model || process.env.AI_ASSIST_DEFAULT_MODEL_OLLAMA || 'qwen2.5:3b'
  const started = Date.now()
  const payload = { model, messages: opts.messages, stream: false }
  const url = `${baseUrl}/api/chat`
  const resp = await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(payload) })
  const txt = await resp.text()
  if (!resp.ok) {
    logger.warn({ status: resp.status, txt }, 'Ollama chat error')
    throw new Error(`ollama_error_${resp.status}`)
  }
  let data: any
  try { data = JSON.parse(txt) } catch {
    // Some ollama versions may stream-like; try to parse last JSON block
    const last = txt.trim().split('\n').filter(Boolean).pop() || '{}'
    data = JSON.parse(last)
  }
  const content: string = data?.message?.content ?? data?.response ?? ''
  return { text: String(content || ''), durationMs: Date.now() - started }
}
