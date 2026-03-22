/**
 * Preview utilities — MIME-type routing and srcdoc builders for FilePreview.
 */

import DOMPurify from 'dompurify'

// ---------------------------------------------------------------------------
// MIME-type routing
// ---------------------------------------------------------------------------

export type PreviewKind = 'image' | 'text' | 'pdf' | 'unsupported'

const TEXT_MIME_TYPES = new Set([
  'text/plain',
  'text/csv',
  'text/markdown',
  'application/json',
])

export function getPreviewKind(mimeType: string): PreviewKind {
  if (mimeType.startsWith('image/')) return 'image'
  if (TEXT_MIME_TYPES.has(mimeType))  return 'text'
  if (mimeType === 'application/pdf') return 'pdf'
  return 'unsupported'
}

// ---------------------------------------------------------------------------
// srcdoc builders — each returns a self-contained HTML string
// ---------------------------------------------------------------------------

function wrapSrcdoc(body: string, extraStyle = ''): string {
  return `<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  html, body { width: 100%; height: 100%; background: #111827; color: #e5e7eb; }
  ${extraStyle}
</style>
</head>
<body>${body}</body>
</html>`
}

export function buildImageSrcdoc(dataUrl: string): string {
  return wrapSrcdoc(
    `<img src="${dataUrl}" alt="preview"
          style="max-width:100%;max-height:100%;display:block;
                 margin:auto;padding:16px;object-fit:contain">`,
    `body { display:flex; align-items:center; justify-content:center; }`
  )
}

export function buildTextSrcdoc(rawText: string): string {
  // Step 1: DOMPurify — strip any HTML tags / event handlers
  const stripped = DOMPurify.sanitize(rawText, { ALLOWED_TAGS: [] })

  // Step 2: HTML-escape so it cannot break out of the <pre> element
  const escaped = stripped
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')

  return wrapSrcdoc(
    `<pre style="padding:16px;font-family:monospace;font-size:13px;
                  white-space:pre-wrap;word-break:break-all;
                  overflow-wrap:break-word">${escaped}</pre>`
  )
}
