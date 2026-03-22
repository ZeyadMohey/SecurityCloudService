/**
 * FileTable — "My Files" tab table with preview / download / share / delete actions.
 */

import { Download, Eye, FileText, Loader2, Share2, Trash2 } from 'lucide-react'
import { sanitizeText } from '../utils/sanitize'
import { ActionButton, XssBadge, formatDate, formatSize } from './DashboardUI'
import type { FileRecord } from '../types'

interface Props {
  files: FileRecord[]
  deleteConfirm: string | null
  deleting: string | null
  downloadingId: string | null
  onPreview: (file: FileRecord) => void
  onDownload: (fileId: string, filename: string) => void
  onShare: (file: FileRecord) => void
  onDeleteConfirm: (fileId: string) => void
  onDelete: (fileId: string) => void
  onDeleteCancel: () => void
}

export default function FileTable({
  files,
  deleteConfirm,
  deleting,
  downloadingId,
  onPreview,
  onDownload,
  onShare,
  onDeleteConfirm,
  onDelete,
  onDeleteCancel,
}: Props) {
  return (
    <div className="border border-gray-800 rounded-xl overflow-hidden">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-gray-800 bg-gray-900/60 text-left text-xs text-gray-500 uppercase tracking-wider">
            <th className="px-4 py-3 font-medium">Name</th>
            <th className="px-4 py-3 font-medium">Size</th>
            <th className="px-4 py-3 font-medium">Uploaded</th>
            <th className="px-4 py-3 font-medium">XSS Scan</th>
            <th className="px-4 py-3 font-medium text-right">Actions</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-gray-800">
          {files.map((file) => (
            <tr key={file.id} className="hover:bg-gray-900/40 transition">
              <td className="px-4 py-3">
                <div className="flex items-center gap-2.5 min-w-0">
                  <FileText className="w-4 h-4 text-gray-500 shrink-0" />
                  <span className="text-white truncate max-w-xs">
                    {sanitizeText(file.originalName)}
                  </span>
                </div>
              </td>
              <td className="px-4 py-3 text-gray-400">{formatSize(file.size)}</td>
              <td className="px-4 py-3 text-gray-400">{formatDate(file.createdAt)}</td>
              <td className="px-4 py-3">
                <XssBadge status={file.xssScanStatus} />
              </td>
              <td className="px-4 py-3">
                <div className="flex items-center gap-1 justify-end">
                  <ActionButton
                    onClick={() => onPreview(file)}
                    label="Preview"
                    icon={<Eye className="w-4 h-4" />}
                  />
                  <ActionButton
                    onClick={() => onDownload(file.id, file.originalName)}
                    loading={downloadingId === file.id}
                    label="Download"
                    icon={<Download className="w-4 h-4" />}
                  />
                  <ActionButton
                    onClick={() => onShare(file)}
                    label="Share"
                    icon={<Share2 className="w-4 h-4" />}
                  />
                  {deleteConfirm === file.id ? (
                    <div className="relative z-50 flex items-center gap-1">
                      <button
                        onClick={() => onDelete(file.id)}
                        disabled={deleting === file.id}
                        className="text-xs px-2 py-1 rounded bg-red-600 hover:bg-red-700 disabled:opacity-50 text-white transition"
                      >
                        {deleting === file.id ? (
                          <Loader2 className="w-3.5 h-3.5 animate-spin" />
                        ) : 'Confirm'}
                      </button>
                      <button
                        onClick={onDeleteCancel}
                        className="text-xs px-2 py-1 rounded bg-gray-700 hover:bg-gray-600 text-gray-300 transition"
                      >
                        Cancel
                      </button>
                    </div>
                  ) : (
                    <ActionButton
                      onClick={() => onDeleteConfirm(file.id)}
                      label="Delete"
                      icon={<Trash2 className="w-4 h-4" />}
                      danger
                    />
                  )}
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
