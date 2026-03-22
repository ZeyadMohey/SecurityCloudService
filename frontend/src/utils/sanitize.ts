import DOMPurify from 'dompurify'

/**
 * Sanitize a string for safe HTML rendering.
 * Uses DOMPurify with a strict allowlist — no scripts, no event handlers.
 */
export function sanitizeHtml(dirty: string): string {
  return DOMPurify.sanitize(dirty, {
    ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'span'],
    ALLOWED_ATTR: [],
  })
}

/**
 * Strip ALL HTML from a server-sourced string — safe for React text nodes.
 * Use this on every piece of text received from the API (filenames, emails,
 * metadata) before rendering, even though React already escapes text nodes.
 * DOMPurify with ALLOWED_TAGS: [] removes tags and event attributes so that
 * any XSS payload embedded in server data is neutralised before React sees it.
 */
export function sanitizeText(text: string): string {
  return DOMPurify.sanitize(text, { ALLOWED_TAGS: [] })
}

/**
 * Escape a string for safe plain-text display (no HTML interpretation).
 */
export function escapeText(text: string): string {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;')
}
