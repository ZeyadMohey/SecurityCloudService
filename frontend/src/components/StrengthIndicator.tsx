/**
 * StrengthIndicator — password strength checklist for the Register page.
 * Shows 4 requirements as green/grey pills.
 */

import { Check } from 'lucide-react'

interface Requirement {
  label: string
  test: (p: string) => boolean
}

export const PASSWORD_REQUIREMENTS: Requirement[] = [
  { label: '8+ characters',    test: (p) => p.length >= 8 },
  { label: 'Uppercase letter', test: (p) => /[A-Z]/.test(p) },
  { label: 'Lowercase letter', test: (p) => /[a-z]/.test(p) },
  { label: 'Number',           test: (p) => /\d/.test(p) },
]

export default function StrengthIndicator({ password }: { password: string }) {
  return (
    <div className="mt-2 grid grid-cols-2 gap-1.5">
      {PASSWORD_REQUIREMENTS.map((req) => {
        const met = req.test(password)
        return (
          <div
            key={req.label}
            className={`flex items-center gap-1.5 text-xs rounded px-2 py-1 ${
              met
                ? 'bg-green-950/60 text-green-400 border border-green-900'
                : 'bg-gray-800 text-gray-500 border border-gray-700'
            }`}
          >
            <Check className={`w-3 h-3 shrink-0 ${met ? 'opacity-100' : 'opacity-20'}`} />
            {req.label}
          </div>
        )
      })}
    </div>
  )
}
