/*
 DashboardNavbar, top navigation bar for the Dashboard page.
*/

import { Shield, LogOut } from "lucide-react";
import { sanitizeText } from "../utils/sanitize";

interface Props {
  email: string;
  onLogout: () => void;
}

export default function DashboardNavbar({ email, onLogout }: Props) {
  return (
    <header className="border-b border-gray-800 bg-gray-900">
      <div className="max-w-5xl mx-auto px-4 h-14 flex items-center justify-between">
        <div className="flex items-center gap-2.5">
          <Shield className="w-5 h-5 text-blue-400" />
          <span className="font-semibold tracking-tight">SecureVault</span>
        </div>
        <div className="flex items-center gap-4">
          <span className="text-sm text-gray-400">{sanitizeText(email)}</span>
          <button
            onClick={onLogout}
            className="flex items-center gap-1.5 text-sm text-gray-400 hover:text-white transition"
          >
            <LogOut className="w-4 h-4" />
            Sign out
          </button>
        </div>
      </div>
    </header>
  );
}
