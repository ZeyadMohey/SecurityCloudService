import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import type { ReactNode } from 'react'
import Login from './pages/Login'
import Register from './pages/Register'
import Dashboard from './pages/Dashboard'

// ---------------------------------------------------------------------------
// Protected route — redirects to /login if the JWT or master key is absent
// ---------------------------------------------------------------------------

function ProtectedRoute({ children }: { children: ReactNode }) {
  const hasToken = !!localStorage.getItem('token')
  const hasMasterKey = !!sessionStorage.getItem('masterKey')

  if (!hasToken || !hasMasterKey) {
    return <Navigate to="/login" replace />
  }

  return <>{children}</>
}

// ---------------------------------------------------------------------------
// App — root router
// ---------------------------------------------------------------------------

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        {/* Public */}
        <Route path="/login"    element={<Login />} />
        <Route path="/register" element={<Register />} />

        {/* Protected */}
        <Route
          path="/dashboard"
          element={
            <ProtectedRoute>
              <Dashboard />
            </ProtectedRoute>
          }
        />

        {/* Catch-all → dashboard (ProtectedRoute redirects to /login if unauthed) */}
        <Route path="*" element={<Navigate to="/dashboard" replace />} />
      </Routes>
    </BrowserRouter>
  )
}
