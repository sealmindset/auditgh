import React from 'react'
import { createRoot } from 'react-dom/client'
import App from './App'
import TopNav from './components/TopNav'
import ProjectsList from './pages/ProjectsList'
import ProjectDetail from './pages/ProjectDetail'
import Home from './pages/Home'
import './styles/tailwind.css'

function Router() {
  const path = window.location.pathname
  if (path === '/') return <Home />
  if (path === '/projects') return <ProjectsList />
  if (path.startsWith('/projects/')) {
    const uuid = path.replace('/projects/', '')
    return <ProjectDetail uuid={uuid} />
  }
  if (path === '/scan' || path === '/scans') return <App />
  return <Home />
}

createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <TopNav />
    <Router />
  </React.StrictMode>
)
