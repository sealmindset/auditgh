import { logger } from '../../config/logging.js'

export type ChatMessage = { role: 'system' | 'user' | 'assistant', content: string }

export async function callOpenAIChat(opts: { apiKey?: string, model?: string, messages: ChatMessage[] }): Promise<{ text: string, durationMs: number }> {
  const apiKey = opts.apiKey || process.env.OPENAI_API_KEY
  if (!apiKey) throw new Error('missing_openai_api_key')
  const model = opts.model || process.env.AI_ASSIST_DEFAULT_MODEL_OPENAI || 'gpt-4o-mini'
  const started = Date.now()
  const payload = { model, messages: opts.messages, temperature: 0.2 }
  const url = 'https://api.openai.com/v1/chat/completions'
  const resp = await fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'authorization': `Bearer ${apiKey}` },
    body: JSON.stringify(payload)
  })
  const txt = await resp.text()
  if (!resp.ok) {
    logger.warn({ status: resp.status, txt }, 'OpenAI chat error')
    throw new Error(`openai_error_${resp.status}`)
  }
  let data: any = {}
  try { data = JSON.parse(txt) } catch {}
  const content: string = data?.choices?.[0]?.message?.content ?? ''
  return { text: String(content || ''), durationMs: Date.now() - started }
}
