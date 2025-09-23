import React, { useMemo } from 'react'

export default function TopNav() {
  const path = useMemo(() => window.location.pathname, [])
  function linkCls(p: string) {
    const active = path === p || (p !== '/' && path.startsWith(p))
    return `px-3 py-1 rounded ${active ? 'bg-blue-600 text-white' : 'text-blue-700 hover:bg-blue-50'}`
  }
  return (
    <header className="w-full border-b bg-white sticky top-0 z-20">
      <div className="max-w-screen-2xl mx-auto px-3 py-2 flex items-center justify-between">
        <div className="font-semibold">Security Portal</div>
        <nav className="flex items-center gap-2 text-sm">
          <a className={linkCls('/')} href="/">Dashboard</a>
          <a className={linkCls('/projects')} href="/projects">Projects</a>
          <a className={linkCls('/scans')} href="/scans">Scans</a>
        </nav>
      </div>
    </header>
  )
}
