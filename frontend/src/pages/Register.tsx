import { useState, type FormEvent } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { useAuth } from '../hooks/useAuth'
import AuthLayout from '../components/AuthLayout'
import FormField from '../components/FormField'
import PasswordInput from '../components/PasswordInput'
import StrengthIndicator, { PASSWORD_REQUIREMENTS } from '../components/StrengthIndicator'

export default function Register() {
  const navigate = useNavigate()
  const { register, loading, error } = useAuth()

  const [email, setEmail]               = useState('')
  const [password, setPassword]         = useState('')
  const [confirm, setConfirm]           = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [fieldErrors, setFieldErrors]   = useState<{
    email?: string; password?: string; confirm?: string
  }>({})

  const passwordStrong = PASSWORD_REQUIREMENTS.every((r) => r.test(password))

  function validate(): boolean {
    const errs: { email?: string; password?: string; confirm?: string } = {}
    if (!email.trim()) errs.email = 'Email is required'
    else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) errs.email = 'Invalid email address'
    if (!password) errs.password = 'Password is required'
    else if (!passwordStrong) errs.password = 'Password does not meet all requirements'
    if (!confirm) errs.confirm = 'Please confirm your password'
    else if (confirm !== password) errs.confirm = 'Passwords do not match'
    setFieldErrors(errs)
    return Object.keys(errs).length === 0
  }

  async function handleSubmit(e: FormEvent) {
    e.preventDefault()
    if (!validate()) return
    const ok = await register(email.trim().toLowerCase(), password)
    if (ok) navigate('/dashboard', { replace: true })
  }

  return (
    <AuthLayout subtitle="Create your encrypted vault">

      {error && (
        <div className="mb-4 px-4 py-3 bg-red-950/60 border border-red-800 rounded-lg text-red-400 text-sm">
          {error}
        </div>
      )}

      <form onSubmit={(e) => { void handleSubmit(e) }} noValidate className="space-y-5">

        <FormField id="email" label="Email address" error={fieldErrors.email}>
          <input
            id="email"
            type="email"
            autoComplete="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            className={`w-full bg-gray-800 border rounded-lg px-3.5 py-2.5 text-white placeholder-gray-600 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition ${
              fieldErrors.email ? 'border-red-700' : 'border-gray-700'
            }`}
            placeholder="you@example.com"
          />
        </FormField>

        <FormField id="password" label="Password" error={fieldErrors.password}>
          <PasswordInput
            id="password"
            value={password}
            onChange={setPassword}
            autoComplete="new-password"
            show={showPassword}
            onToggleShow={() => setShowPassword((s) => !s)}
            hasError={!!fieldErrors.password}
          />
          {password.length > 0 && <StrengthIndicator password={password} />}
        </FormField>

        <FormField id="confirm" label="Confirm password" error={fieldErrors.confirm}>
          <input
            id="confirm"
            type={showPassword ? 'text' : 'password'}
            autoComplete="new-password"
            value={confirm}
            onChange={(e) => setConfirm(e.target.value)}
            className={`w-full bg-gray-800 border rounded-lg px-3.5 py-2.5 text-white placeholder-gray-600 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition ${
              fieldErrors.confirm ? 'border-red-700' : 'border-gray-700'
            }`}
            placeholder="••••••••"
          />
        </FormField>

        <button
          type="submit"
          disabled={loading}
          className="w-full bg-blue-600 hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed text-white font-medium text-sm rounded-lg py-2.5 transition"
        >
          {loading ? 'Creating account…' : 'Create account'}
        </button>
      </form>

      <p className="mt-6 text-center text-sm text-gray-500">
        Already have an account?{' '}
        <Link to="/login" className="text-blue-400 hover:text-blue-300 transition">
          Sign in
        </Link>
      </p>

    </AuthLayout>
  )
}
