/**
 * ShareModal — ECDH-based file sharing dialog (Paper [9])
 *
 * Lets the owner:
 *  • Search for recipient users by email (GET /api/users/search)
 *  • Choose 'view' or 'download' permission
 *  • Submit the share (POST /api/files/:id/share)
 *  • Revoke an existing share (DELETE /api/files/:id/share/:shareId)
 *
 * All server-supplied strings (emails, filenames) are passed through
 * sanitizeText (DOMPurify, ALLOWED_TAGS: []) before render per Papers [1,2].
 */

import { useState, useEffect, useCallback } from 'react'
import { X, UserPlus, Trash2, Loader2 } from 'lucide-react'
import axios from 'axios'
import apiClient from '../api/client'
import { sanitizeText } from '../utils/sanitize'
import UserSearchInput from './UserSearchInput'
import type { FileRecord, ApiError } from '../types'

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface ShareRecord {
  shareId: string
  sharedWith: string
  permission: 'view' | 'download'
  sharedAt: string
}

interface UserSuggestion {
  id: string
  email: string
}

interface Props {
  file: FileRecord
  onClose: () => void
  onSharesUpdated: () => void
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export default function ShareModal({ file, onClose, onSharesUpdated }: Props) {
  const [shares, setShares]               = useState<ShareRecord[]>([])
  const [loadingShares, setLoadingShares] = useState(true)

  const [email, setEmail]                 = useState('')
  const [suggestions, setSuggestions]     = useState<UserSuggestion[]>([])
  const [showSuggestions, setShowSuggestions] = useState(false)
  const [permission, setPermission]       = useState<'view' | 'download'>('view')
  const [submitting, setSubmitting]       = useState(false)
  const [revoking, setRevoking]           = useState<string | null>(null)

  const [formError, setFormError]         = useState<string | null>(null)
  const [shareSuccess, setShareSuccess]   = useState<string | null>(null)

  // ── Load existing shares ─────────────────────────────────────────────────

  const loadShares = useCallback(async () => {
    setLoadingShares(true)
    try {
      const { data } = await apiClient.get<ShareRecord[]>(`/files/${file.id}/shares`)
      setShares(data)
    } catch {
      // Non-critical — modal still usable
    } finally {
      setLoadingShares(false)
    }
  }, [file.id])

  useEffect(() => { void loadShares() }, [loadShares])

  // ── Close on Escape ──────────────────────────────────────────────────────

  useEffect(() => {
    const handler = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose() }
    window.addEventListener('keydown', handler)
    return () => window.removeEventListener('keydown', handler)
  }, [onClose])

  // ── Submit share ─────────────────────────────────────────────────────────

  async function handleShare() {
    setFormError(null)
    setShareSuccess(null)

    const trimmedEmail = email.trim().toLowerCase()
    if (!trimmedEmail) { setFormError('Email is required'); return }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(trimmedEmail)) {
      setFormError('Invalid email address')
      return
    }

    setSubmitting(true)
    try {
      await apiClient.post(`/files/${file.id}/share`, { email: trimmedEmail, permission })
      setEmail('')
      setSuggestions([])
      setShowSuggestions(false)
      setShareSuccess(`Shared with ${sanitizeText(trimmedEmail)}`)
      await loadShares()
      onSharesUpdated()
    } catch (err) {
      if (axios.isAxiosError(err) && err.response?.data) {
        setFormError((err.response.data as ApiError).message)
      } else {
        setFormError('Share failed. Please try again.')
      }
    } finally {
      setSubmitting(false)
    }
  }

  // ── Revoke share ─────────────────────────────────────────────────────────

  async function handleRevoke(shareId: string) {
    setRevoking(shareId)
    try {
      await apiClient.delete(`/files/${file.id}/share/${shareId}`)
      setShares((prev) => prev.filter((s) => s.shareId !== shareId))
      onSharesUpdated()
    } catch {
      // Keep entry visible — user can retry
    } finally {
      setRevoking(null)
    }
  }

  // ── Render ───────────────────────────────────────────────────────────────

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 px-4"
      onClick={(e) => { if (e.target === e.currentTarget) onClose() }}
    >
      <div className="w-full max-w-md bg-gray-900 border border-gray-800 rounded-xl shadow-2xl">

        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-gray-800">
          <div>
            <h2 className="text-sm font-semibold text-white">Share file</h2>
            <p className="text-xs text-gray-500 mt-0.5 truncate max-w-xs">
              {sanitizeText(file.originalName)}
            </p>
          </div>
          <button onClick={onClose} className="text-gray-500 hover:text-gray-300 transition" aria-label="Close">
            <X className="w-5 h-5" />
          </button>
        </div>

        <div className="px-6 py-5 space-y-5">

          {/* Add share form */}
          <div className="space-y-3">
            <UserSearchInput
              value={email}
              suggestions={suggestions}
              showSuggestions={showSuggestions}
              onChange={(v) => { setEmail(v); setFormError(null); setShareSuccess(null) }}
              onSuggestions={setSuggestions}
              onShowSuggestions={setShowSuggestions}
              onSelect={(s) => { setEmail(s.email); setSuggestions([]); setShowSuggestions(false) }}
            />

            <div>
              <label className="block text-xs font-medium text-gray-400 mb-1.5">Permission</label>
              <select
                value={permission}
                onChange={(e) => setPermission(e.target.value as 'view' | 'download')}
                className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3.5 py-2.5 text-sm text-white focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition"
              >
                <option value="view">View only</option>
                <option value="download">View &amp; Download</option>
              </select>
            </div>

            {formError && <p className="text-xs text-red-400">{formError}</p>}
            {shareSuccess && <p className="text-xs text-green-400">{shareSuccess}</p>}

            <button
              onClick={() => { void handleShare() }}
              disabled={submitting}
              className="w-full flex items-center justify-center gap-2 bg-blue-600 hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed text-white text-sm font-medium rounded-lg py-2.5 transition"
            >
              {submitting ? <Loader2 className="w-4 h-4 animate-spin" /> : <UserPlus className="w-4 h-4" />}
              {submitting ? 'Sharing…' : 'Share'}
            </button>
          </div>

          {/* Existing shares */}
          {(loadingShares || shares.length > 0) && (
            <div>
              <h3 className="text-xs font-medium text-gray-400 mb-2">Shared with</h3>
              {loadingShares ? (
                <div className="flex items-center gap-2 text-xs text-gray-500 py-2">
                  <Loader2 className="w-3.5 h-3.5 animate-spin" /> Loading…
                </div>
              ) : (
                <ul className="space-y-1.5">
                  {shares.map((s) => (
                    <li
                      key={s.shareId}
                      className="flex items-center justify-between gap-2 px-3 py-2 bg-gray-800/60 rounded-lg border border-gray-700"
                    >
                      <div className="min-w-0">
                        <p className="text-sm text-white truncate">{sanitizeText(s.sharedWith)}</p>
                        <p className="text-xs text-gray-500 capitalize">{s.permission}</p>
                      </div>
                      <button
                        onClick={() => { void handleRevoke(s.shareId) }}
                        disabled={revoking === s.shareId}
                        className="shrink-0 text-gray-500 hover:text-red-400 disabled:opacity-40 transition"
                        aria-label={`Revoke access for ${sanitizeText(s.sharedWith)}`}
                      >
                        {revoking === s.shareId
                          ? <Loader2 className="w-4 h-4 animate-spin" />
                          : <Trash2 className="w-4 h-4" />}
                      </button>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
