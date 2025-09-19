import React from 'react'
import { createRoot } from 'react-dom/client'
import App from './App'
import ProjectsList from './pages/ProjectsList'
import ProjectDetail from './pages/ProjectDetail'
import './styles/tailwind.css'

function Router() {
  const path = window.location.pathname
  if (path === '/projects') return <ProjectsList />
  if (path.startsWith('/projects/')) {
    const uuid = path.replace('/projects/', '')
    return <ProjectDetail uuid={uuid} />
  }
  return <App />
}

createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <Router />
  </React.StrictMode>
)
