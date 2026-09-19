import { useEffect, useRef, useState } from 'react'
import {
  CheckCircle2,
  Copy,
  Database,
  ExternalLink,
  Instagram,
  Mail,
  MessageCircle,
  RefreshCw,
  ShieldCheck,
  Unplug,
  Wrench,
  XCircle,
} from 'lucide-react'
import api from '../api'

const providers = [
  {
    id: 'gmail',
    name: 'Gmail',
    description: 'Import and analyze support emails with real-time NLP classification, sentiment analysis, and risk scoring.',
    icon: Mail,
    color: 'text-red-600',
    bg: 'bg-red-50',
    isUnderConstruction: false,
  },
  {
    id: 'instagram',
    name: 'Instagram DMs',
    description: 'Monitor and respond to customer messages from your Instagram business account with AI security analysis.',
    icon: Instagram,
    color: 'text-pink-600',
    bg: 'bg-pink-50',
    isUnderConstruction: false,
  },
  {
    id: 'whatsapp',
    name: 'WhatsApp Business',
    description: 'Connect customer conversations through Meta’s official Cloud API.',
    icon: MessageCircle,
    color: 'text-emerald-600',
    bg: 'bg-emerald-50',
    isUnderConstruction: false,
  },
]

const apiOrigin = import.meta.env.VITE_API_URL || 'http://localhost:8000'
const webhookUrl = (provider) => `${apiOrigin.replace(/\/$/, '')}/webhooks/${provider}`

export default function Connections() {
  const [statuses, setStatuses] = useState([])
  const [loading, setLoading] = useState(true)
  const [working, setWorking] = useState('')
  const [error, setError] = useState('')
  const [message, setMessage] = useState('')
  const [expanded, setExpanded] = useState('')

  const popup = useRef(null)

  const load = async () => {
    setLoading(true)
    setError('')
    try {
      const { data } = await api.get('/connections/status')
      setStatuses(data)
    } catch (err) {
      setError(err.response?.data?.detail || 'Could not load connection status.')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    load()
    const onMessage = (event) => {
      if (event.origin === window.location.origin && event.data?.sentideskOAuth) {
        setMessage(event.data.message || 'Authorization response received.')
        popup.current = null
        load()
      }
    }
    window.addEventListener('message', onMessage)
    const timer = window.setInterval(() => {
      if (!popup.current) return
      try {
        if (popup.current.closed) {
          popup.current = null
          load()
        }
      } catch {
        // Cross-Origin-Opener-Policy / cross-origin DOM exception:
        // Ignore access restrictions while popup is navigated to external OAuth provider domain
      }
    }, 1000)
    return () => {
      window.removeEventListener('message', onMessage)
      window.clearInterval(timer)
    }
  }, [])

  const connectOAuth = async (provider) => {
    setWorking(provider)
    setError('')
    setMessage('')
    try {
      const { data } = await api.get(`/connections/${provider}/oauth/start`)
      if (!data.authorization_url) throw new Error('The server did not return an authorization URL.')
      const width = 520,
        height = 700,
        left = window.screenX + (window.outerWidth - width) / 2,
        top = window.screenY + (window.outerHeight - height) / 2
      popup.current = window.open(
        data.authorization_url,
        `${provider}-authorization`,
        `width=${width},height=${height},left=${left},top=${top}`
      )
      if (!popup.current) window.location.assign(data.authorization_url)
      else setMessage(`Continue in the ${provider} authorization window. This page will update when it closes.`)
    } catch (err) {
      setError(err.response?.data?.detail || err.message || `Could not start ${provider} authorization.`)
    } finally {
      setWorking('')
    }
  }

  const disconnect = async (provider) => {
    setWorking(provider)
    setError('')
    try {
      const { data } = await api.post(`/connections/${provider}/disconnect`)
      setStatuses((items) => items.map((item) => (item.provider === provider ? data : item)))
      setMessage(`${provider[0].toUpperCase() + provider.slice(1)} disconnected.`)
    } catch (err) {
      setError(err.response?.data?.detail || `Could not disconnect ${provider}.`)
    } finally {
      setWorking('')
    }
  }

  const statusFor = (id) => statuses.find((item) => item.provider === id)
  const copy = async (text) => {
    try {
      await navigator.clipboard.writeText(text)
      setMessage('Webhook URL copied to clipboard.')
    } catch {
      setMessage(text)
    }
  }

  return (
    <>
      <div className="mb-8 flex flex-wrap items-start justify-between gap-3">
        <div>
          <h1 className="text-2xl font-black text-slate-900">Connections</h1>
          <p className="mt-1 text-slate-500">Securely connect your Gmail support inbox and analyze customer emails with NLP intelligence.</p>
        </div>
        <button onClick={load} disabled={loading} className="btn-ghost flex items-center gap-2">
          <RefreshCw size={16} className={loading ? 'animate-spin' : ''} /> Refresh status
        </button>
      </div>

      <div className="mb-6 flex items-start gap-3 rounded-2xl border border-indigo-100 bg-indigo-50 p-4 text-sm text-indigo-800">
        <ShieldCheck className="mt-0.5 shrink-0" size={19} />
        <p>
          <strong>Your data stays yours.</strong> OAuth and webhook API tokens are stored securely on the server.
          SentiDesk never asks for account passwords or stores credentials in your browser.
        </p>
      </div>

      {error && (
        <div className="mb-5 flex items-center justify-between gap-3 rounded-xl bg-rose-50 p-4 text-sm text-rose-700 border border-rose-200">
          <span className="flex items-center gap-2">
            <XCircle size={17} />
            {error}
          </span>
          <button onClick={load} className="font-bold underline">
            Retry
          </button>
        </div>
      )}

      {message && <div className="mb-5 rounded-xl bg-emerald-50 p-4 text-sm text-emerald-700 border border-emerald-200">{message}</div>}

      <div className="grid gap-5 lg:grid-cols-3">
        {providers.map(({ id, name, description, icon: Icon, color, bg, isUnderConstruction }) => {
          const status = statusFor(id)
          const connected = status?.status === 'connected'
          const unavailable = status && !status.configured
          return (
            <div className={`card flex flex-col p-6 shadow-sm ${isUnderConstruction ? 'bg-slate-50/50 border-slate-200' : ''}`} key={id}>
              <div className="flex items-start justify-between">
                <div className={`flex h-12 w-12 items-center justify-center rounded-xl ${bg} ${color}`}>
                  <Icon />
                </div>
                {isUnderConstruction ? (
                  <span className="inline-flex items-center gap-1.5 rounded-full bg-amber-100 px-3 py-1 text-xs font-extrabold text-amber-800 border border-amber-300">
                    <Wrench size={13} /> Under Construction
                  </span>
                ) : loading ? (
                  <span className="h-5 w-20 animate-pulse rounded bg-slate-100" />
                ) : (
                  <span
                    className={`flex items-center gap-1 text-xs font-bold ${
                      connected ? 'text-emerald-600' : unavailable ? 'text-amber-600' : 'text-slate-400'
                    }`}
                  >
                    {connected ? (
                      <>
                        <CheckCircle2 size={15} /> Connected {status.connected_email ? `(${status.connected_email})` : ''}
                      </>
                    ) : unavailable ? (
                      'Setup needed'
                    ) : (
                      'Not connected'
                    )}
                  </span>
                )}
              </div>

              <h2 className="mt-5 text-lg font-bold text-slate-900">{name}</h2>
              <p className="mt-2 min-h-12 text-sm leading-6 text-slate-500">{description}</p>

              {isUnderConstruction ? (
                <div className="mt-4 rounded-xl bg-amber-50/80 border border-amber-200 px-3 py-2.5 text-xs leading-5 text-amber-800 font-medium">
                  Under Construction. System focus is currently prioritized on Gmail Inbox & Deep NLP Processing.
                </div>
              ) : (
                unavailable && <p className="mt-4 rounded-lg bg-amber-50 px-3 py-2 text-xs leading-5 text-amber-700">{status.message}</p>
              )}

              <div className="mt-auto pt-6 flex flex-col gap-2">
                {isUnderConstruction ? (
                  <button disabled className="btn-ghost w-full flex items-center justify-center gap-2 text-xs font-bold text-slate-400 bg-slate-100 cursor-not-allowed">
                    <Wrench size={14} /> Under Construction
                  </button>
                ) : connected ? (
                  <button
                    onClick={() => disconnect(id)}
                    disabled={loading || working === id}
                    className="btn-ghost w-full flex items-center justify-center gap-2 text-rose-600 hover:bg-rose-50"
                  >
                    {working === id ? <RefreshCw size={16} className="animate-spin" /> : <Unplug size={16} />}
                    Disconnect
                  </button>
                ) : (
                  <button
                    onClick={() => connectOAuth(id)}
                    disabled={loading || !status || working === id}
                    className="btn-primary w-full flex items-center justify-center gap-2"
                  >
                    {working === id ? (
                      <RefreshCw size={16} className="animate-spin" />
                    ) : (
                      <ExternalLink size={16} />
                    )}
                    {working === id ? 'Working…' : 'Authorize securely'}
                  </button>
                )}
              </div>
            </div>
          )
        })}
      </div>

      <div className="mt-6 grid gap-5 md:grid-cols-2">
        <div className="card p-6 shadow-sm">
          <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-indigo-50 text-indigo-600">
            <Database />
          </div>
          <h2 className="mt-5 text-lg font-bold text-slate-900">SentiDesk Dataset</h2>
          <p className="mt-2 text-sm text-slate-500">Local conversation data powered by the FastAPI backend.</p>
          <DatasetSync />
        </div>
        <div className="card p-6 shadow-sm">
          <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-slate-100 text-slate-600">
            <ShieldCheck />
          </div>
          <h2 className="mt-5 text-lg font-bold text-slate-900">Connection health</h2>
          <p className="mt-2 text-sm leading-6 text-slate-500">
            Gmail imports when you request a sync. Natural Language Processing (NLP) runs locally on imported emails.
            Instagram and WhatsApp are currently under construction while email NLP features are prioritized.
          </p>
        </div>
      </div>
    </>
  )
}

function DatasetSync() {
  const [syncing, setSyncing] = useState(false)
  const [message, setMessage] = useState('')
  const sync = async () => {
    setSyncing(true)
    setMessage('')
    try {
      const { data } = await api.post('/sync')
      setMessage(data.message || `Synced ${data.count ?? ''} conversations.`)
    } catch (err) {
      setMessage(err.response?.data?.detail || 'Sync failed. Please try again.')
    } finally {
      setSyncing(false)
    }
  }
  return (
    <>
      <button onClick={sync} disabled={syncing} className="btn-primary mt-6 flex items-center gap-2">
        <RefreshCw size={16} className={syncing ? 'animate-spin' : ''} />
        {syncing ? 'Syncing…' : 'Sync dataset'}
      </button>
      {message && <p className="mt-3 text-sm text-slate-600">{message}</p>}
    </>
  )
}
