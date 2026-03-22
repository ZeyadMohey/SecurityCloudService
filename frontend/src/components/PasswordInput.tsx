/**
 * PasswordInput — text/password input with show/hide toggle.
 * Used by both Login and Register.
 */

import { Eye, EyeOff } from 'lucide-react'

interface Props {
  id: string
  value: string
  onChange: (value: string) => void
  autoComplete: string
  show: boolean
  onToggleShow: () => void
  hasError: boolean
}

export default function PasswordInput({
  id,
  value,
  onChange,
  autoComplete,
  show,
  onToggleShow,
  hasError,
}: Props) {
  return (
    <div className="relative">
      <input
        id={id}
        type={show ? 'text' : 'password'}
        autoComplete={autoComplete}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className={`w-full bg-gray-800 border rounded-lg px-3.5 py-2.5 pr-10 text-white placeholder-gray-600 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition ${
          hasError ? 'border-red-700' : 'border-gray-700'
        }`}
        placeholder="••••••••"
      />
      <button
        type="button"
        onClick={onToggleShow}
        className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-500 hover:text-gray-300 transition"
        aria-label={show ? 'Hide password' : 'Show password'}
      >
        {show ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
      </button>
    </div>
  )
}
