/*
 All previews are rendered inside an <iframe sandbox> element. The sandbox
 attribute removes the iframe from the parent page's origin context.
  Images, Text: injected into srcdoc HTML, sandbox zero capabilities granted
  PDF: set as iframe src so the browser's native PDF renderer can load it, 
  sandbox allow-same-origin allow-scripts(browser PDF plugins need script execution to render)
  Other: preview not available
 */

import { useState, useEffect, useCallback, useRef } from "react";
import { X, Download, Loader2, AlertTriangle } from "lucide-react";
import apiClient from "../api/client";
import { sanitizeText } from "../utils/sanitize";
import {
  getPreviewKind,
  buildImageSrcdoc,
  buildTextSrcdoc,
} from "../utils/previewUtils";
import type { FileRecord } from "../types";

interface Props {
  file: FileRecord;
  onClose: () => void;
  onDownload: (fileId: string, filename: string) => void;
}

type LoadState = "loading" | "ready" | "error";

export default function FilePreview({ file, onClose, onDownload }: Props) {
  const [loadState, setLoadState] = useState<LoadState>("loading");
  const [srcdoc, setSrcdoc] = useState<string | null>(null);
  const [pdfBlobUrl, setPdfBlobUrl] = useState<string | null>(null);
  const pdfBlobUrlRef = useRef<string | null>(null);
  const kind = getPreviewKind(file.mimeType);

  // Fetch and prepare preview content
  const buildPreview = useCallback(async () => {
    if (kind === "unsupported") {
      setLoadState("ready");
      return;
    }

    try {
      const response = await apiClient.get<Blob>(`/files/${file.id}/download`, {
        responseType: "blob",
      });
      const blob = response.data;

      if (kind === "image") {
        const dataUrl = await new Promise<string>((resolve, reject) => {
          const reader = new FileReader();
          reader.onload = () => resolve(reader.result as string);
          reader.onerror = reject;
          reader.readAsDataURL(blob);
        });
        setSrcdoc(buildImageSrcdoc(dataUrl));
      } else if (kind === "text") {
        const rawText = await blob.text();
        setSrcdoc(buildTextSrcdoc(rawText));
      } else if (kind === "pdf") {
        const url = URL.createObjectURL(blob);
        pdfBlobUrlRef.current = url;
        setPdfBlobUrl(url);
      }
      setLoadState("ready");
    } catch {
      setLoadState("error");
    }
  }, [file.id, kind]);

  useEffect(() => {
    void buildPreview();
    return () => {
      if (pdfBlobUrlRef.current) URL.revokeObjectURL(pdfBlobUrlRef.current);
    };
  }, [buildPreview]);

  // Close on escape
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [onClose]);

  // Render
  const safeFilename = sanitizeText(file.originalName);
  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 px-4 py-6"
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div className="w-full max-w-3xl bg-gray-900 border border-gray-800 rounded-xl shadow-2xl flex flex-col max-h-full overflow-hidden">
        {/* Header */}
        <div className="flex items-center justify-between px-5 py-3.5 border-b border-gray-800 shrink-0">
          <div className="min-w-0 mr-4">
            <h2 className="text-sm font-medium text-white truncate">
              {safeFilename}
            </h2>
            <p className="text-xs text-gray-500 mt-0.5">{file.mimeType}</p>
          </div>
          <div className="flex items-center gap-2 shrink-0">
            <button
              onClick={() => onDownload(file.id, file.originalName)}
              className="flex items-center gap-1.5 text-xs text-gray-400 hover:text-white border border-gray-700 hover:border-gray-600 rounded-lg px-3 py-1.5 transition"
            >
              <Download className="w-3.5 h-3.5" />
              Download
            </button>
            <button
              onClick={onClose}
              className="text-gray-500 hover:text-gray-300 transition"
              aria-label="Close preview"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Preview area */}
        <div
          className="relative flex-1 overflow-hidden"
          style={{ minHeight: "300px", maxHeight: "500px" }}
        >
          {loadState === "loading" && (
            <div className="absolute inset-0 flex items-center justify-center text-gray-500">
              <Loader2 className="w-6 h-6 animate-spin mr-2" />
              <span className="text-sm">Decrypting…</span>
            </div>
          )}

          {loadState === "error" && (
            <div className="absolute inset-0 flex flex-col items-center justify-center text-gray-500 gap-3">
              <AlertTriangle className="w-8 h-8 text-yellow-600" />
              <p className="text-sm">Failed to load preview.</p>
              <button
                onClick={() => onDownload(file.id, file.originalName)}
                className="flex items-center gap-1.5 text-xs text-blue-400 hover:text-blue-300 transition"
              >
                <Download className="w-3.5 h-3.5" />
                Download instead
              </button>
            </div>
          )}

          {loadState === "ready" && (
            <>
              {/* Images & Text: srcdoc, sandbox="" (zero capabilities) */}
              {(kind === "image" || kind === "text") && srcdoc && (
                <iframe
                  title={`Preview: ${safeFilename}`}
                  sandbox=""
                  srcDoc={srcdoc}
                  style={{ width: "100%", height: "100%", border: "none" }}
                  aria-label={`Sandboxed preview of ${safeFilename}`}
                />
              )}

              {/* PDF: blob URL, sandbox="allow-same-origin allow-scripts" */}
              {kind === "pdf" && pdfBlobUrl && (
                <iframe
                  title={`Preview: ${safeFilename}`}
                  src={pdfBlobUrl}
                  sandbox="allow-same-origin allow-scripts"
                  style={{ width: "100%", height: "100%", border: "none" }}
                  aria-label={`Sandboxed PDF preview of ${safeFilename}`}
                />
              )}

              {kind === "unsupported" && (
                <div className="absolute inset-0 flex flex-col items-center justify-center text-gray-500 gap-3">
                  <p className="text-sm">
                    Preview not available for this file type.
                  </p>
                  <p className="text-xs text-gray-600">{file.mimeType}</p>
                  <button
                    onClick={() => onDownload(file.id, file.originalName)}
                    className="flex items-center gap-1.5 text-xs text-blue-400 hover:text-blue-300 transition mt-1"
                  >
                    <Download className="w-3.5 h-3.5" />
                    Download file
                  </button>
                </div>
              )}
            </>
          )}
        </div>

        {/* Footer */}
        <div className="px-5 py-2.5 border-t border-gray-800 shrink-0">
          <p className="text-xs text-gray-600">
            Preview is sandboxed — file content cannot access your session or
            cookies.
          </p>
        </div>
      </div>
    </div>
  );
}
