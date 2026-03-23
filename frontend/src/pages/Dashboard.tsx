/*
 Dashboard: main file management UI
 
 Two tabs:
  My Files: owned files with upload / download / delete / share
  Shared With Me:  files shared by others with optional download

 Every string received from the server passed through sanitizeText () before render
 the X-Master-Key header is injected by the Axios interceptor (api/client.ts), this component never touches raw key bytes.
*/

import { useState, useEffect, useRef, useCallback } from "react";
import type { ChangeEvent } from "react";
import { Upload, Loader2 } from "lucide-react";
import axios from "axios";
import apiClient from "../api/client";
import { useAuth } from "../hooks/useAuth";
import { sanitizeText } from "../utils/sanitize";
import ShareModal from "../components/ShareModal";
import FilePreview from "../components/FilePreview";
import FileTable from "../components/FileTable";
import SharedFilesTable from "../components/SharedFilesTable";
import DashboardNavbar from "../components/DashboardNavbar";
import { LoadingState, EmptyState } from "../components/DashboardUI";
import type { FileRecord, SharedFile, ApiError } from "../types";

// Helpers
function readEmail(): string {
  const token = localStorage.getItem("token");
  if (!token) return "";
  try {
    const payload = JSON.parse(atob(token.split(".")[1])) as { email?: string };
    return payload.email ?? "";
  } catch {
    return "";
  }
}

// Dashboard
type Tab = "mine" | "shared";

export default function Dashboard() {
  const { logout } = useAuth();
  const email = readEmail();
  const [tab, setTab] = useState<Tab>("mine");
  const [ownedFiles, setOwnedFiles] = useState<FileRecord[]>([]);
  const [sharedFiles, setSharedFiles] = useState<SharedFile[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [uploading, setUploading] = useState(false);
  const [uploadError, setUploadError] = useState<string | null>(null);
  const [deleteConfirm, setDeleteConfirm] = useState<string | null>(null);
  const [deleting, setDeleting] = useState<string | null>(null);
  const [downloadingId, setDownloadingId] = useState<string | null>(null);
  const [shareModalFile, setShareModalFile] = useState<FileRecord | null>(null);
  const [previewFile, setPreviewFile] = useState<FileRecord | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Data loading
  const loadFiles = useCallback(async () => {
    setLoading(true);
    setLoadError(null);
    try {
      const [ownedRes, sharedRes] = await Promise.all([
        apiClient.get<{ owned: FileRecord[]; shared: SharedFile[] }>("/files"),
        apiClient.get<SharedFile[]>("/files/shared-with-me"),
      ]);
      setOwnedFiles(ownedRes.data.owned);
      setSharedFiles(sharedRes.data);
    } catch {
      setLoadError("Failed to load files. Please refresh.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadFiles();
  }, [loadFiles]);

  //Upload
  async function handleFileChange(e: ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file) return;
    e.target.value = "";
    setUploadError(null);
    setUploading(true);
    const formData = new FormData();
    formData.append("file", file);
    try {
      await apiClient.post("/files/upload", formData, {
        headers: { "Content-Type": "multipart/form-data" },
      });
      await loadFiles();
    } catch (err) {
      if (axios.isAxiosError(err) && err.response?.data) {
        setUploadError((err.response.data as ApiError).message);
      } else {
        setUploadError("Upload failed. Please try again.");
      }
    } finally {
      setUploading(false);
    }
  }

  // Download
  async function handleDownload(fileId: string, filename: string) {
    setDownloadingId(fileId);
    try {
      const response = await apiClient.get<Blob>(`/files/${fileId}/download`, {
        responseType: "blob",
      });
      const url = URL.createObjectURL(response.data);
      const a = document.createElement("a");
      a.href = url;
      a.download = sanitizeText(filename);
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch {
      // Silently handle   user remains on page
    } finally {
      setDownloadingId(null);
    }
  }

  // Delete
  async function handleDelete(fileId: string) {
    setDeleting(fileId);
    try {
      await apiClient.delete(`/files/${fileId}`);
      setOwnedFiles((prev) => prev.filter((f) => f.id !== fileId));
      setDeleteConfirm(null);
    } catch {
      // Keep file in list   delete failed
    } finally {
      setDeleting(null);
    }
  }

  // Render

  return (
    <div className="min-h-screen bg-gray-950 text-white">
      <DashboardNavbar email={email} onLogout={logout} />

      <main className="max-w-5xl mx-auto px-4 py-8">
        {/* Tab bar, Upload button */}
        <div className="flex items-center justify-between mb-6">
          <nav className="flex gap-1 bg-gray-900 border border-gray-800 rounded-lg p-1">
            {(["mine", "shared"] as Tab[]).map((t) => (
              <button
                key={t}
                onClick={() => setTab(t)}
                className={`px-4 py-1.5 text-sm font-medium rounded-md transition ${
                  tab === t
                    ? "bg-blue-600 text-white"
                    : "text-gray-400 hover:text-white"
                }`}
              >
                {t === "mine" ? (
                  "My Files"
                ) : (
                  <>
                    Shared With Me
                    {sharedFiles.length > 0 && (
                      <span className="ml-1.5 text-xs bg-blue-500/20 text-blue-300 px-1.5 py-0.5 rounded-full">
                        {sharedFiles.length}
                      </span>
                    )}
                  </>
                )}
              </button>
            ))}
          </nav>

          {tab === "mine" && (
            <div className="flex items-center gap-3">
              {uploadError && (
                <p className="text-xs text-red-400">{uploadError}</p>
              )}
              <button
                onClick={() => fileInputRef.current?.click()}
                disabled={uploading}
                className="flex items-center gap-2 bg-blue-600 hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed text-white text-sm font-medium rounded-lg px-4 py-2 transition"
              >
                {uploading ? (
                  <Loader2 className="w-4 h-4 animate-spin" />
                ) : (
                  <Upload className="w-4 h-4" />
                )}
                {uploading ? "Uploading…" : "Upload"}
              </button>
              <input
                ref={fileInputRef}
                type="file"
                className="hidden"
                onChange={(e) => {
                  void handleFileChange(e);
                }}
              />
            </div>
          )}
        </div>

        {loadError && (
          <div className="mb-4 px-4 py-3 bg-red-950/60 border border-red-800 rounded-lg text-red-400 text-sm">
            {loadError}
          </div>
        )}

        {/* My Files tab */}
        {tab === "mine" &&
          (loading ? (
            <LoadingState />
          ) : ownedFiles.length === 0 ? (
            <EmptyState message="No files yet   upload your first file above." />
          ) : (
            <FileTable
              files={ownedFiles}
              deleteConfirm={deleteConfirm}
              deleting={deleting}
              downloadingId={downloadingId}
              onPreview={setPreviewFile}
              onDownload={(id, name) => {
                void handleDownload(id, name);
              }}
              onShare={setShareModalFile}
              onDeleteConfirm={setDeleteConfirm}
              onDelete={(id) => {
                void handleDelete(id);
              }}
              onDeleteCancel={() => setDeleteConfirm(null)}
            />
          ))}

        {/* Shared With Me tab */}
        {tab === "shared" &&
          (loading ? (
            <LoadingState />
          ) : sharedFiles.length === 0 ? (
            <EmptyState message="No files have been shared with you yet." />
          ) : (
            <SharedFilesTable
              files={sharedFiles}
              downloadingId={downloadingId}
              onPreview={setPreviewFile}
              onDownload={(id, name) => {
                void handleDownload(id, name);
              }}
            />
          ))}
      </main>

      {shareModalFile && (
        <ShareModal
          file={shareModalFile}
          onClose={() => setShareModalFile(null)}
          onSharesUpdated={() => {
            void loadFiles();
          }}
        />
      )}

      {previewFile && (
        <FilePreview
          file={previewFile}
          onClose={() => setPreviewFile(null)}
          onDownload={(fileId, filename) => {
            void handleDownload(fileId, filename);
          }}
        />
      )}

      {deleteConfirm && (
        <div
          className="fixed inset-0 z-40"
          onClick={() => setDeleteConfirm(null)}
        />
      )}

      {/* Security features badge   Paper [1–15] */}
      <footer className="border-t border-gray-800/60 mt-8 py-4 bg-gray-950">
        <div className="max-w-5xl mx-auto px-4">
          <p className="text-xs text-gray-600 text-center tracking-wide">
            <span className="text-gray-500 font-medium">SecureVault</span>
            {" - "}
            <span className="text-green-600">CSP Nonce</span>
            {" ✓ "}
            <span className="text-green-600">AES-256-GCM</span>
            {" ✓ "}
            <span className="text-green-600">ECC Key Exchange</span>
            {" ✓ "}
            <span className="text-green-600">XSS Scanner</span>
            {" ✓ "}
            <span className="text-green-600">Container Isolation</span>
            {" ✓"}
          </p>
        </div>
      </footer>
    </div>
  );
}
