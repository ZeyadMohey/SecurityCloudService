import axios from 'axios'

/**
 * Central Axios instance for all SecureVault API calls.
 *
 * baseURL uses the Vite dev proxy (/api → http://localhost:3001/api) so that
 * all requests are same-origin in development and avoid CORS preflight
 * overhead.  In production the proxy is replaced by the reverse proxy / CDN.
 */
const apiClient = axios.create({
  baseURL: '/api',
  headers: { 'Content-Type': 'application/json' },
})

// ── Request interceptors ────────────────────────────────────────────────────

apiClient.interceptors.request.use((config) => {
  // 1. JWT Bearer token — persisted in localStorage across sessions
  const token = localStorage.getItem('token')
  if (token) {
    config.headers.Authorization = `Bearer ${token}`
  }

  // 2. Master key — base64-encoded 32-byte PBKDF2 key held in sessionStorage
  //    (cleared when the tab closes, unlike localStorage).
  //    The server decodes this to decrypt per-file keys without ever receiving
  //    the raw password again after initial login.
  const masterKey = sessionStorage.getItem('masterKey')
  if (masterKey) {
    config.headers['X-Master-Key'] = masterKey
  }

  return config
})

// ── Response interceptors ───────────────────────────────────────────────────

apiClient.interceptors.response.use(
  (response) => response,
  (error: unknown) => {
    if (axios.isAxiosError(error) && error.response?.status === 401) {
      // Clear both credentials — user must re-authenticate and re-derive the key
      localStorage.removeItem('token')
      sessionStorage.removeItem('masterKey')
      window.location.href = '/login'
    }
    return Promise.reject(error)
  }
)

export default apiClient
