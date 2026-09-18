import { useEffect, useState } from 'react'
import { CheckCircle2, Mail, ShieldCheck } from 'lucide-react'
import { useAuth } from '../context/AuthContext'
import { useNavigate } from 'react-router-dom'
import api from '../api'

function getErrorMessage(error, fallback = 'Unable to authenticate. Check your details.') {
  const detail = error?.response?.data?.detail
  if (typeof detail === 'string') return detail
  if (Array.isArray(detail)) return detail.map(item => item?.msg || 'Invalid input').join(' ')
  return fallback
}

export default function Login() {
  const { login, register } = useAuth()
  const navigate = useNavigate()
  const [isRegister, setRegister] = useState(false)
  const [form, setForm] = useState({ email: '', password: '', code: '' })
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const [verificationSent, setVerificationSent] = useState(false)
  const [verified, setVerified] = useState(false)

  useEffect(() => {
    const token = new URLSearchParams(window.location.search).get('token')
    if (!token) return
    setBusy(true)
    api.post('/auth/verify-email', { token })
      .then(() => setVerified(true))
      .catch(err => setError(getErrorMessage(err, 'This verification link is invalid or expired.')))
      .finally(() => setBusy(false))
  }, [])

  const submit = async event => {
    event.preventDefault()
    setError('')
    setBusy(true)
    try {
      if (verificationSent) {
        await api.post('/auth/verify', { email: form.email, code: form.code })
        setVerified(true)
        setVerificationSent(false)
        setRegister(false)
        setForm(current => ({ ...current, code: '' }))
      } else {
        const result = isRegister ? await register(form) : await login(form)
        if (isRegister && result?.verification_required) setVerificationSent(true)
        else navigate('/')
      }
    } catch (err) {
      setError(getErrorMessage(err))
    } finally {
      setBusy(false)
    }
  }

  const toggle = () => {
    setRegister(value => !value)
    setError('')
    setVerificationSent(false)
  }

  return <div className="flex min-h-screen items-center justify-center bg-gradient-to-br from-indigo-50 via-white to-slate-100 p-5">
    <div className="w-full max-w-md">
      <div className="mb-8 text-center">
        <div className="mx-auto mb-4 flex h-14 w-14 items-center justify-center rounded-2xl bg-indigo-600 text-white"><ShieldCheck size={30} /></div>
        <h1 className="text-3xl font-black text-slate-900">SentiDesk</h1>
        <p className="mt-2 text-slate-500">AI support intelligence and threat detection</p>
      </div>
      {verificationSent ? <form onSubmit={submit} className="card p-7 text-center">
        <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-full bg-indigo-50 text-indigo-600"><Mail /></div>
        <h2 className="mt-4 text-xl font-bold">Verify your account</h2>
        <p className="mt-2 text-sm leading-6 text-slate-500">Enter the 6-digit code sent to <strong className="text-slate-700">{form.email}</strong>.</p>
        <input required minLength="6" maxLength="6" inputMode="numeric" value={form.code} onChange={event => setForm({ ...form, code: event.target.value.replace(/\D/g, '') })} placeholder="000000" className="mt-5 w-full rounded-xl border p-3 text-center text-xl tracking-[.5em] outline-none focus:border-indigo-500" />
        {error && <div className="mt-4 rounded-xl bg-rose-50 p-3 text-sm text-rose-600">{error}</div>}
        <button disabled={busy} className="btn-primary mt-5 w-full">{busy ? 'Verifying…' : 'Verify email'}</button>
        <button type="button" onClick={toggle} className="mt-5 text-sm font-semibold text-indigo-600">Back to sign in</button>
      </form> : <form onSubmit={submit} className="card p-7">
        <h2 className="mb-6 text-xl font-bold">{isRegister ? 'Create your workspace' : 'Welcome back'}</h2>
        {verified && <div className="mb-4 flex gap-2 rounded-xl bg-emerald-50 p-3 text-sm text-emerald-700"><CheckCircle2 size={18} /> Email verified. You can sign in now.</div>}
        <label className="mb-4 block text-sm font-semibold text-slate-600">Email
          <input required type="email" value={form.email} onChange={event => setForm({ ...form, email: event.target.value })} placeholder="you@company.com" className="mt-1 w-full rounded-xl border p-3 font-normal outline-none focus:border-indigo-500" />
        </label>
        <label className="mb-5 block text-sm font-semibold text-slate-600">Password
          <input required minLength={isRegister ? 8 : undefined} type="password" value={form.password} onChange={event => setForm({ ...form, password: event.target.value })} placeholder={isRegister ? 'At least 8 characters' : 'Your password'} className="mt-1 w-full rounded-xl border p-3 font-normal outline-none focus:border-indigo-500" />
        </label>
        {isRegister && <p className="mb-4 text-xs leading-5 text-slate-500">A verification code must be entered before this account is created.</p>}
        {error && <div className="mb-4 rounded-xl bg-rose-50 p-3 text-sm text-rose-600">{error}</div>}
        <button disabled={busy} className="btn-primary w-full">{busy ? 'Please wait…' : isRegister ? 'Create account' : 'Sign in'}</button>
        <button type="button" onClick={toggle} className="mt-5 w-full text-sm font-semibold text-indigo-600">{isRegister ? 'Already have an account? Sign in' : 'Create a new account'}</button>
      </form>}
    </div>
  </div>
}
