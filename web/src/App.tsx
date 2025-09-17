import { useEffect, useState } from 'react'

function AuthBadge() {
  const [status, setStatus] = useState<{authDisabled:boolean, authenticated:boolean} | null>(null)
  useEffect(() => {
    fetch('/auth/me').then(r => r.json()).then(setStatus).catch(() => {})
  }, [])
  if (!status?.authDisabled) return null
  return <div className="bg-yellow-100 text-yellow-800 text-xs px-2 py-1 rounded">AUTH DISABLED (DEV ONLY)</div>
}

export default function App() {
  return (
    <div className="min-h-screen bg-slate-50 text-slate-900">
      <header className="flex items-center justify-between p-4 border-b bg-white sticky top-0">
        <h1 className="font-semibold">Security Portal</h1>
        <AuthBadge />
      </header>
      <main className="p-4">
        <p className="text-sm opacity-70 mb-4">Phase 1 scaffold. Use docker-compose.portal.yml to run the stack.</p>
        <div className="bg-white p-4 rounded shadow-sm">
          <h2 className="font-medium mb-2">Projects</h2>
          <p className="text-sm">Projects UI will be implemented in Phase 3.</p>
        </div>
      </main>
    </div>
  )
}
