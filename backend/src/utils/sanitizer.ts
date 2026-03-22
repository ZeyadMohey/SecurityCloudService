/**
 * Input sanitization utilities — Paper [1] (Hannousse) layered defense strategy.
 *
 * Two layers:
 *  1. sanitizeFilename — allowlist regex strips anything not in [A-Za-z0-9._\- ]
 *  2. encodeHtml — context-aware HTML entity encoding for metadata displayed in HTML
 */

/** Allowlist: alphanumerics, dots, hyphens, underscores, spaces. */
const SAFE_FILENAME_RE = /[^A-Za-z0-9.\-_ ]/g

/**
 * Strips characters not on the allowlist from a filename.
 * Collapses repeated dots to prevent path traversal sequences like `..`.
 */
export function sanitizeFilename(name: string): string {
  const stripped = name.replace(SAFE_FILENAME_RE, '')
  // Collapse consecutive dots to prevent `../` traversal after stripping
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
 * HTML entity-encodes a string for safe insertion into HTML context.
 * Covers OWASP XSS Prevention Cheat Sheet Rule #1.
 */
export function encodeHtml(text: string): string {
  return text.replace(/[&<>"'/]/g, (ch) => HTML_ENTITIES[ch] ?? ch)
}
