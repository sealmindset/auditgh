import { logger } from '../config/logging.js'

type Provider = 'openai'|'anthropic'|'cohere'|'gemini'|'mistral'|'huggingface'|'stability'|'together'|'replicate'|'perplexity'|'xai'|'openrouter'|string

function envTrue(name: string, def = true): boolean {
  const raw = (process.env[name] || '').toLowerCase()
  if (!raw) return def
  return ['1','true','yes','on'].includes(raw)
}

const MASTER = envTrue('VALIDATE_GENAI_TOKENS', true)

const ENABLED: Record<string, boolean> = {
  openai: envTrue('VALIDATE_OPENAI_TOKENS', true),
  anthropic: envTrue('VALIDATE_ANTHROPIC_TOKENS', true),
  cohere: envTrue('VALIDATE_COHERE_TOKENS', true),
  gemini: envTrue('VALIDATE_GEMINI_TOKENS', true),
  mistral: envTrue('VALIDATE_MISTRAL_TOKENS', true),
  huggingface: envTrue('VALIDATE_HUGGINGFACE_TOKENS', true),
  stability: envTrue('VALIDATE_STABILITY_TOKENS', true),
  together: envTrue('VALIDATE_TOGETHER_TOKENS', true),
  replicate: envTrue('VALIDATE_REPLICATE_TOKENS', true),
  perplexity: envTrue('VALIDATE_PERPLEXITY_TOKENS', true),
  xai: envTrue('VALIDATE_XAI_TOKENS', true),
  openrouter: envTrue('VALIDATE_OPENROUTER_TOKENS', true),
}

async function checkOpenAI(token: string): Promise<{ status: 'valid'|'invalid'|'error', http: number, error?: string }>{
  try {
    const res = await fetch('https://api.openai.com/v1/models', {
      method: 'GET',
      headers: { Authorization: `Bearer ${token}` },
    })
    if (res.status === 200) return { status: 'valid', http: 200 }
    if (res.status === 401 || res.status === 403) return { status: 'invalid', http: res.status }
    return { status: 'error', http: res.status, error: await res.text().catch(()=>'') }
  } catch (e: any) {
    return { status: 'error', http: 0, error: String(e?.message || e) }
  }
}

async function checkAnthropic(token: string): Promise<{ status: 'valid'|'invalid'|'error', http: number, error?: string }>{
  try {
    const res = await fetch('https://api.anthropic.com/v1/models', {
      method: 'GET',
      headers: { 'x-api-key': token, 'anthropic-version': '2023-06-01' },
    })
    if (res.status === 200) return { status: 'valid', http: 200 }
    if (res.status === 401 || res.status === 403) return { status: 'invalid', http: res.status }
    return { status: 'error', http: res.status, error: await res.text().catch(()=>'') }
  } catch (e: any) {
    return { status: 'error', http: 0, error: String(e?.message || e) }
  }
}

async function checkCohere(token: string): Promise<{ status: 'valid'|'invalid'|'error', http: number, error?: string }>{
  try {
    // Cohere uses Bearer auth; list models is a cheap auth-protected endpoint
    const res = await fetch('https://api.cohere.ai/v1/models', { method: 'GET', headers: { Authorization: `Bearer ${token}` } })
    if (res.status === 200) return { status: 'valid', http: 200 as const }
    if (res.status === 401 || res.status === 403) return { status: 'invalid', http: res.status as number }
    return { status: 'error', http: res.status as number, error: await res.text().catch(()=>'' ) }
  } catch (e: any) { return { status: 'error', http: 0, error: String(e?.message || e) } }
}

// Google Generative Language (Gemini) validates via key query param
async function checkGemini(token: string): Promise<{ status: 'valid'|'invalid'|'error', http: number, error?: string }>{
  try {
    const url = `https://generativelanguage.googleapis.com/v1/models?key=${encodeURIComponent(token)}`
    const res = await fetch(url, { method: 'GET' })
    if (res.status === 200) return { status: 'valid', http: 200 as const }
    if (res.status === 401 || res.status === 403) return { status: 'invalid', http: res.status as number }
    return { status: 'error', http: res.status as number, error: await res.text().catch(()=>'' ) }
  } catch (e: any) { return { status: 'error', http: 0, error: String(e?.message || e) } }
}

// Mistral uses Bearer auth
async function checkMistral(token: string): Promise<{ status: 'valid'|'invalid'|'error', http: number, error?: string }>{
  try {
    const res = await fetch('https://api.mistral.ai/v1/models', { method: 'GET', headers: { Authorization: `Bearer ${token}` } })
    if (res.status === 200) return { status: 'valid', http: 200 as const }
    if (res.status === 401 || res.status === 403) return { status: 'invalid', http: res.status as number }
    return { status: 'error', http: res.status as number, error: await res.text().catch(()=>'' ) }
  } catch (e: any) { return { status: 'error', http: 0, error: String(e?.message || e) } }
}

async function checkHuggingFace(token: string): Promise<{ status: 'valid'|'invalid'|'error', http: number, error?: string }>{
  try {
    // whoami-v2 is cheap and auth-protected
    const res = await fetch('https://huggingface.co/api/whoami-v2', { method: 'GET', headers: { Authorization: `Bearer ${token}` } })
    if (res.status === 200) return { status: 'valid', http: 200 as const }
    if (res.status === 401 || res.status === 403) return { status: 'invalid', http: res.status as number }
    return { status: 'error', http: res.status as number, error: await res.text().catch(()=>'' ) }
  } catch (e: any) { return { status: 'error', http: 0, error: String(e?.message || e) } }
}

async function checkStability(token: string): Promise<{ status: 'valid'|'invalid'|'error', http: number, error?: string }>{
  try {
    const res = await fetch('https://api.stability.ai/v1/user/account', { method: 'GET', headers: { Authorization: `Bearer ${token}` } })
    if (res.status === 200) return { status: 'valid', http: 200 as const }
    if (res.status === 401 || res.status === 403) return { status: 'invalid', http: res.status as number }
    return { status: 'error', http: res.status as number, error: await res.text().catch(()=>'' ) }
  } catch (e: any) { return { status: 'error', http: 0, error: String(e?.message || e) } }
}

async function checkTogether(token: string): Promise<{ status: 'valid'|'invalid'|'error', http: number, error?: string }>{
  try {
    const res = await fetch('https://api.together.xyz/v1/models', { method: 'GET', headers: { Authorization: `Bearer ${token}` } })
    if (res.status === 200) return { status: 'valid', http: 200 as const }
    if (res.status === 401 || res.status === 403) return { status: 'invalid', http: res.status as number }
    return { status: 'error', http: res.status as number, error: await res.text().catch(()=>'' ) }
  } catch (e: any) { return { status: 'error', http: 0, error: String(e?.message || e) } }
}

async function checkReplicate(token: string): Promise<{ status: 'valid'|'invalid'|'error', http: number, error?: string }>{
  try {
    const res = await fetch('https://api.replicate.com/v1/models', { method: 'GET', headers: { Authorization: `Bearer ${token}` } })
    if (res.status === 200) return { status: 'valid', http: 200 as const }
    if (res.status === 401 || res.status === 403) return { status: 'invalid', http: res.status as number }
    return { status: 'error', http: res.status as number, error: await res.text().catch(()=>'' ) }
  } catch (e: any) { return { status: 'error', http: 0, error: String(e?.message || e) } }
}

async function checkPerplexity(token: string): Promise<{ status: 'valid'|'invalid'|'error', http: number, error?: string }>{
  try {
    const res = await fetch('https://api.perplexity.ai/models', { method: 'GET', headers: { Authorization: `Bearer ${token}` } })
    if (res.status === 200) return { status: 'valid', http: 200 as const }
    if (res.status === 401 || res.status === 403) return { status: 'invalid', http: res.status as number }
    return { status: 'error', http: res.status as number, error: await res.text().catch(()=>'' ) }
  } catch (e: any) { return { status: 'error', http: 0, error: String(e?.message || e) } }
}

async function checkXai(token: string): Promise<{ status: 'valid'|'invalid'|'error', http: number, error?: string }>{
  try {
    const res = await fetch('https://api.x.ai/v1/models', { method: 'GET', headers: { Authorization: `Bearer ${token}` } })
    if (res.status === 200) return { status: 'valid', http: 200 as const }
    if (res.status === 401 || res.status === 403) return { status: 'invalid', http: res.status as number }
    return { status: 'error', http: res.status as number, error: await res.text().catch(()=>'' ) }
  } catch (e: any) { return { status: 'error', http: 0, error: String(e?.message || e) } }
}

async function checkOpenRouter(token: string): Promise<{ status: 'valid'|'invalid'|'error', http: number, error?: string }>{
  try {
    const res = await fetch('https://openrouter.ai/api/v1/models', { method: 'GET', headers: { Authorization: `Bearer ${token}` } })
    if (res.status === 200) return { status: 'valid', http: 200 as const }
    if (res.status === 401 || res.status === 403) return { status: 'invalid', http: res.status as number }
    return { status: 'error', http: res.status as number, error: await res.text().catch(()=>'' ) }
  } catch (e: any) { return { status: 'error', http: 0, error: String(e?.message || e) } }
}

export async function validateToken(provider: Provider, token: string): Promise<{ status: 'valid'|'invalid'|'error', http: number, error?: string }>{
  if (!MASTER) return { status: 'error', http: 0, error: 'Validation disabled' }
  const p = provider.toLowerCase()
  if (p === 'openai' && ENABLED.openai) return checkOpenAI(token)
  if (p === 'anthropic' && ENABLED.anthropic) return checkAnthropic(token)
  if (p === 'cohere' && ENABLED.cohere) return checkCohere(token)
  if (p === 'gemini' && ENABLED.gemini) return checkGemini(token)
  if (p === 'mistral' && ENABLED.mistral) return checkMistral(token)
  if (p === 'huggingface' && ENABLED.huggingface) return checkHuggingFace(token)
  if (p === 'stability' && ENABLED.stability) return checkStability(token)
  if (p === 'together' && ENABLED.together) return checkTogether(token)
  if (p === 'replicate' && ENABLED.replicate) return checkReplicate(token)
  if (p === 'perplexity' && ENABLED.perplexity) return checkPerplexity(token)
  if (p === 'xai' && ENABLED.xai) return checkXai(token)
  if (p === 'openrouter' && ENABLED.openrouter) return checkOpenRouter(token)
  // Default: unknown provider, mark error
  return { status: 'error', http: 0, error: `No validator for provider ${provider}` }
}

export async function validateAndRecord(postgrestUrl: string, aiTokenApiId: number, provider: string, token: string): Promise<void> {
  const res = await validateToken(provider, token)
  try {
    await fetch(`${postgrestUrl}/rpc/record_ai_token_validation`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ p_ai_token_id: aiTokenApiId, p_status: res.status, p_http_status: res.http, p_error: res.error || null }),
    })
  } catch (e) {
    logger.warn({ e }, 'Failed to record ai token validation')
  }
}
