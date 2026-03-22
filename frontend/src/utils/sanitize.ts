import DOMPurify from "dompurify";

/*
 Sanitize a string for safe HTML rendering.
 Uses DOMPurify with a strict allowlist, no scripts, no event handlers.
*/
export function sanitizeHtml(dirty: string): string {
  return DOMPurify.sanitize(dirty, {
    ALLOWED_TAGS: ["b", "i", "em", "strong", "span"],
    ALLOWED_ATTR: [],
  });
}

/*
 This function strips all HTML and XSS payloads from server-sourced strings using DOMPurify with no allowed tags.
 It provides an essential extra layer of defense for metadata and text nodes before they are rendered in React.
*/
export function sanitizeText(text: string): string {
  return DOMPurify.sanitize(text, { ALLOWED_TAGS: [] });
}

/*
 Escape a string for safe plain-text display (no HTML interpretation).
*/
export function escapeText(text: string): string {
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}
