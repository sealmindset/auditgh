import { toPng } from 'html-to-image'

export async function toPNG(node: HTMLElement, fileName: string): Promise<void> {
  const dataUrl = await toPng(node, { cacheBust: true, pixelRatio: 2 })
  downloadDataUrl(dataUrl, fileName)
}

export function toSVG(svgNode: SVGElement, fileName: string): void {
  const serializer = new XMLSerializer()
  const source = serializer.serializeToString(svgNode)
  const blob = new Blob([source], { type: 'image/svg+xml;charset=utf-8' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = fileName
  a.click()
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}

export function fromSeriesToCSV(rows: Array<Record<string, any>>, headers?: string[]): string {
  if (!rows || rows.length === 0) return ''
  const cols = headers && headers.length ? headers : Array.from(new Set(rows.flatMap(r => Object.keys(r))))
  const esc = (v: any) => {
    const s = v === undefined || v === null ? '' : String(v)
    if (/[",\n]/.test(s)) return '"' + s.replace(/"/g, '""') + '"'
    return s
  }
  const out: string[] = []
  out.push(cols.join(','))
  for (const r of rows) out.push(cols.map(c => esc(r[c])).join(','))
  return out.join('\n')
}

function downloadDataUrl(dataUrl: string, fileName: string) {
  const a = document.createElement('a')
  a.href = dataUrl
  a.download = fileName
  a.click()
}
