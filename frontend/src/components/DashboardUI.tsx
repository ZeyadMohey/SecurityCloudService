/**
 * Shared micro-components and utilities for the Dashboard.
 * Keeps Dashboard.tsx focused on orchestration.
 */

import { Shield, AlertTriangle, Clock, Loader2 } from 'lucide-react'
import type { FileRecord } from '../types'

// ---------------------------------------------------------------------------
// Formatters
// ---------------------------------------------------------------------------

export function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
}

export function formatDate(iso: string): string {
  return new Date(iso).toLocaleDateString(undefined, {
    year: 'numeric', month: 'short', day: 'numeric',
  })
}

// ---------------------------------------------------------------------------
// XssBadge
// ---------------------------------------------------------------------------

export function XssBadge({ status }: { status: FileRecord['xssScanStatus'] }) {
  if (status === 'clean') {
    return (
      <span className="inline-flex items-center gap-1 text-xs px-2 py-0.5 rounded-full bg-green-950/60 text-green-400 border border-green-900">
        <Shield className="w-3 h-3" /> Clean
      </span>
    )
  }
  if (status === 'flagged') {
    return (
      <span className="inline-flex items-center gap-1 text-xs px-2 py-0.5 rounded-full bg-red-950/60 text-red-400 border border-red-900">
        <AlertTriangle className="w-3 h-3" /> Flagged
      </span>
    )
  }
  return (
    <span className="inline-flex items-center gap-1 text-xs px-2 py-0.5 rounded-full bg-yellow-950/60 text-yellow-500 border border-yellow-900">
      <Clock className="w-3 h-3" /> Scanning
    </span>
  )
}

// ---------------------------------------------------------------------------
// ActionButton
// ---------------------------------------------------------------------------

export interface ActionButtonProps {
  onClick: () => void
  label: string
  icon: React.ReactNode
  loading?: boolean
  danger?: boolean
}

export function ActionButton({ onClick, label, icon, loading = false, danger = false }: ActionButtonProps) {
  return (
    <button
      onClick={onClick}
      disabled={loading}
      title={label}
      aria-label={label}
      className={`p-1.5 rounded transition disabled:opacity-40 ${
        danger
          ? 'text-gray-500 hover:text-red-400 hover:bg-red-950/30'
          : 'text-gray-500 hover:text-white hover:bg-gray-700'
      }`}
    >
      {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : icon}
    </button>
  )
}

// ---------------------------------------------------------------------------
// LoadingState / EmptyState
// ---------------------------------------------------------------------------

export function LoadingState() {
  return (
    <div className="flex items-center justify-center py-20 text-gray-500">
      <Loader2 className="w-6 h-6 animate-spin mr-2" />
      <span className="text-sm">Loading…</span>
    </div>
  )
}

export function EmptyState({ message }: { message: string }) {
  return (
    <div className="border border-gray-800 border-dashed rounded-xl py-20 flex flex-col items-center justify-center text-center">
      <Shield className="w-10 h-10 text-gray-700 mb-3" />
      <p className="text-gray-500 text-sm">{message}</p>
    </div>
  )
}
