/** Allowlist: alphanumerics, dots, hyphens, underscores, spaces. */
const SAFE_FILENAME_RE = /[^A-Za-z0-9.\-_ ]/g

/**
 * Strips characters not on the allowlist from a filename.
 * Collapses repeated dots to prevent path traversal sequences like `..`.
 */
export function sanitizeFilename(name: string): string {
  const stripped = name.replace(SAFE_FILENAME_RE, '')
  return stripped.replace(/\.{2,}/g, '.').trim() || 'upload'
}

const HTML_ENTITIES: Record<string, string> = {
  '&': '&amp;',
  '<': '&lt;',
  '>': '&gt;',
  '"': '&quot;',
  "'": '&#x27;',
  '/': '&#x2F;',
}

/**
 *
 * HTML entity-encodes a string for safe insertion into HTML context.
 */
export function encodeHtml(text: string): string {
  return text.replace(/[&<>"'/]/g, (ch) => HTML_ENTITIES[ch] ?? ch)
}
