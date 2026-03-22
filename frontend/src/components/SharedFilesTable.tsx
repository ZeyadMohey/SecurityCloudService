/*Shared With Me tab table (Preview available, download needs permission)*/

import { Download, Eye, FileText } from "lucide-react";
import { sanitizeText } from "../utils/sanitize";
import { ActionButton, formatDate } from "./DashboardUI";
import type { SharedFile } from "../types";

interface Props {
  files: SharedFile[];
  downloadingId: string | null;
  onPreview: (file: SharedFile["file"]) => void;
  onDownload: (fileId: string, filename: string) => void;
}

export default function SharedFilesTable({
  files,
  downloadingId,
  onPreview,
  onDownload,
}: Props) {
  return (
    <div className="border border-gray-800 rounded-xl overflow-hidden">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-gray-800 bg-gray-900/60 text-left text-xs text-gray-500 uppercase tracking-wider">
            <th className="px-4 py-3 font-medium">Name</th>
            <th className="px-4 py-3 font-medium">Shared By</th>
            <th className="px-4 py-3 font-medium">Permission</th>
            <th className="px-4 py-3 font-medium">Shared On</th>
            <th className="px-4 py-3 font-medium text-right">Actions</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-gray-800">
          {files.map((sf) => (
            <tr key={sf.shareId} className="hover:bg-gray-900/40 transition">
              <td className="px-4 py-3">
                <div className="flex items-center gap-2.5 min-w-0">
                  <FileText className="w-4 h-4 text-gray-500 shrink-0" />
                  <span className="text-white truncate max-w-xs">
                    {sanitizeText(sf.file.originalName)}
                  </span>
                </div>
              </td>
              <td className="px-4 py-3 text-gray-400">
                {sanitizeText(sf.sharedBy)}
              </td>
              <td className="px-4 py-3">
                <span
                  className={`text-xs px-2 py-0.5 rounded-full border capitalize ${
                    sf.permission === "download"
                      ? "bg-blue-950/40 text-blue-400 border-blue-900"
                      : "bg-gray-800 text-gray-400 border-gray-700"
                  }`}
                >
                  {sf.permission}
                </span>
              </td>
              <td className="px-4 py-3 text-gray-400">
                {formatDate(sf.sharedAt)}
              </td>
              <td className="px-4 py-3">
                <div className="flex items-center gap-1 justify-end">
                  <ActionButton
                    onClick={() => onPreview(sf.file)}
                    label="Preview"
                    icon={<Eye className="w-4 h-4" />}
                  />
                  {sf.permission === "download" && (
                    <ActionButton
                      onClick={() =>
                        onDownload(sf.file.id, sf.file.originalName)
                      }
                      loading={downloadingId === sf.file.id}
                      label="Download"
                      icon={<Download className="w-4 h-4" />}
                    />
                  )}
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
