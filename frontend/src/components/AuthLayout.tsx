/*
 AuthLayout, shared outer shell for Login and Register pages.
 Renders the SecureVault logo header and card wrapper.
*/

import { Shield } from "lucide-react";

interface Props {
  subtitle: string;
  children: React.ReactNode;
}

export default function AuthLayout({ subtitle, children }: Props) {
  return (
    <div className="min-h-screen bg-gray-950 flex items-center justify-center p-4">
      <div className="w-full max-w-md">
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-14 h-14 rounded-full bg-blue-600/10 border border-blue-600/20 mb-4">
            <Shield className="w-7 h-7 text-blue-400" />
          </div>
          <h1 className="text-2xl font-bold text-white">SecureVault</h1>
          <p className="text-gray-500 text-sm mt-1">{subtitle}</p>
        </div>

        <div className="bg-gray-900 border border-gray-800 rounded-xl shadow-xl p-8">
          {children}
        </div>
      </div>
    </div>
  );
}
