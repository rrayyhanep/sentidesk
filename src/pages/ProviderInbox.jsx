import { useCallback, useEffect, useMemo, useState } from 'react'
import {
  AlertCircle, AlertTriangle, BarChart2, CheckCircle2, ChevronDown, ChevronUp,
  Clock3, Filter, Inbox, Instagram, Mail, MessageCircle, RefreshCw,
  Search, Send, ShieldAlert, ShieldCheck, Tag, TrendingUp, Wrench, X, Eye
} from 'lucide-react'
import { Link, NavLink, useParams } from 'react-router-dom'
import api from '../api'
import Loading from '../components/Loading'
import Badge from '../components/Badge'
import CombinedIntelligencePanel from '../components/CombinedIntelligencePanel'

const providers = {
  gmail: {
    name: 'Mails Inbox',
    description: 'Import and analyze support emails with complaint categorization, sentiment analysis, issue extraction, conversation summarization, phishing URL detection, social engineering detection, and 4-tier risk scoring.',
    syncLabel: 'Refresh Inbox',
    icon: Mail,
    isUnderConstruction: false,
  },
  instagram: {
    name: 'Instagram DMs',
    description: 'Instagram Direct Messages channel with real-time AI security threat detection and customer support intelligence.',
    syncLabel: 'Check for messages',
    icon: Instagram,
    isUnderConstruction: false,
  },
  whatsapp: {
    name: 'WhatsApp Business',
    description: 'WhatsApp Business Cloud API integration for sending & receiving messages with real-time AI security & intelligence analysis.',
    syncLabel: 'Check for messages',
    icon: MessageCircle,
    isUnderConstruction: false,
  },
}

const avatarColors = [
  'bg-indigo-100 text-indigo-700 border-indigo-200',
  'bg-emerald-100 text-emerald-700 border-emerald-200',
  'bg-violet-100 text-violet-700 border-violet-200',
  'bg-amber-100 text-amber-700 border-amber-200',
  'bg-rose-100 text-rose-700 border-rose-200',
  'bg-sky-100 text-sky-700 border-sky-200',
]

function getAvatarColor(name) {
  let hash = 0
  for (let i = 0; i < (name || '').length; i++) {
    hash = (hash << 5) - hash + name.charCodeAt(i)
  }
  return avatarColors[Math.abs(hash) % avatarColors.length]
}

function parseSender(senderStr) {
  if (!senderStr) return { name: 'Unknown Sender', email: '' }
  const match = senderStr.match(/^(.*?)\s*<([^>]+)>$/)
  if (match) {
    const rawName = match[1].trim().replace(/^["']|["']$/g, '')
    return { name: rawName || match[2], email: match[2] }
  }
  if (senderStr.includes('@')) {
    return { name: senderStr.split('@')[0], email: senderStr }
  }
  return { name: senderStr, email: '' }
}

function formatDate(dateStr) {
  if (!dateStr) return 'No timestamp'
  try {
    const d = new Date(dateStr)
    if (isNaN(d.getTime())) return dateStr
    return d.toLocaleString(undefined, {
      month: 'short', day: 'numeric', year: 'numeric', hour: '2-digit', minute: '2-digit'
    })
  } catch {
    return dateStr
  }
}

const errorText = (err, fallback) => err.response?.data?.detail || fallback

async function withAnalysis(messages) {
  if (!messages || !messages.length) return []
  const pending = messages.filter((message) => !message.analysis)
  if (!pending.length) return messages
  try {
    const { data } = await api.post('/analyze/bulk', {
      messages: pending.map((message) => ({
        role: 'customer',
        content: message.content,
        timestamp: message.timestamp,
      })),
    })
    let index = 0
    return messages.map((message) =>
      message.analysis ? message : { ...message, analysis: data[index++]?.analysis }
    )
  } catch {
    return messages
  }
}

function FormattedContent({ text }) {
  if (!text) return null
  return (
    <div className="mt-3 text-xs leading-relaxed text-slate-700 bg-slate-50/70 p-3.5 rounded-xl border border-slate-100 font-sans whitespace-pre-wrap">
      {text}
    </div>
  )
}

export default function ProviderInbox() {
  const { provider: routeProvider } = useParams()
  const provider = routeProvider || 'gmail'
  const meta = providers[provider] || providers.gmail

  const [status, setStatus] = useState(null)
  const [messages, setMessages] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [activeTab, setActiveTab] = useState('inbox')
  const [syncing, setSyncing] = useState(false)
  const [syncMessage, setSyncMessage] = useState('')
  const [query, setQuery] = useState('')
  const [selectedIssue, setSelectedIssue] = useState(null)
  const [quickFilter, setQuickFilter] = useState('all') // 'all' | 'threats' | 'support' | 'unresolved' | 'resolved'

  // WhatsApp outbound message state
  const [waTo, setWaTo] = useState('')
  const [waMessage, setWaMessage] = useState('')
  const [waSending, setWaSending] = useState(false)
  const [waSendSuccess, setWaSendSuccess] = useState('')
  const [waSendError, setWaSendError] = useState('')
  const [updatingStatusId, setUpdatingStatusId] = useState(null)

  const handleToggleResolutionStatus = async (message) => {
    if (!message) return
    const msgId = message.external_id
    if (!msgId) return

    const currentStatus = message.analysis?.resolution_status || message.status || 'Unresolved'
    const newStatus = currentStatus.toLowerCase() === 'resolved' ? 'Unresolved' : 'Resolved'

    setUpdatingStatusId(msgId)
    try {
      await api.post('/api/messages/status', {
        provider,
        external_id: msgId,
        resolution_status: newStatus,
      })

      // Optimistically update local messages array
      setMessages((prev) =>
        (prev || []).map((m) => {
          if (m.external_id === msgId) {
            const updatedAnalysis = m.analysis
              ? { ...m.analysis, resolution_status: newStatus }
              : { resolution_status: newStatus }
            return {
              ...m,
              status: newStatus,
              analysis: updatedAnalysis,
            }
          }
          return m
        })
      )
    } catch (err) {
      console.error('Failed to update resolution status:', err)
      setError(errorText(err, 'Could not update message resolution status.'))
    } finally {
      setUpdatingStatusId(null)
    }
  }

  const handleSendWhatsApp = async (e) => {
    e.preventDefault()
    if (!waTo || !waMessage) return
    setWaSending(true)
    setWaSendError('')
    setWaSendSuccess('')
    try {
      const { data } = await api.post('/connections/whatsapp/send', {
        to: waTo.trim(),
        message: waMessage.trim(),
      })
      setWaSendSuccess(`WhatsApp message sent successfully! (ID: ${data.message_id || 'OK'})`)
      setWaMessage('')
      load({ quiet: true })
    } catch (err) {
      const msg = err.response?.data?.detail || err.message || 'Failed to send WhatsApp message.'
      setWaSendError(msg)
    } finally {
      setWaSending(false)
    }
  }

  const load = useCallback(
    async ({ quiet = false } = {}) => {
      if (!quiet) setLoading(true)
      setError('')
      try {
        const { data: connection } = await api.get(`/connections/${provider}/status`)
        setStatus(connection)
        if (connection.status !== 'connected') {
          setMessages(null)
          return
        }
        const { data } = await api.get('/api/messages', { params: { provider } })
        let inbox = data.messages || []
        // Auto-fetch initial raw emails upon fresh connection if inbox is empty
        if (!inbox.length) {
          try {
            const { data: syncData } = await api.post('/refresh', null, { params: { provider } })
            inbox = syncData.messages || []
          } catch {
            // Ignore if provider is unconfigured
          }
        }
        setMessages(inbox)
      } catch (err) {
        setError(errorText(err, `Could not load ${meta.name} inbox.`))
      } finally {
        setLoading(false)
      }
    },
    [provider, meta.name]
  )

  const sync = async () => {
    setSyncing(true)
    setSyncMessage('')
    setError('')
    try {
      const { data } = await api.post('/refresh', null, { params: { provider } })
      setSyncMessage(
        data.message || `Refresh triggered! Messages loaded from database; AI categorization active for new items.`
      )
      setMessages(data.messages || [])
    } catch (err) {
      setError(errorText(err, `Could not refresh ${meta.name} inbox.`))
    } finally {
      setSyncing(false)
    }
  }

  useEffect(() => {
    load()
  }, [load])

  // Post-login / Post-connection listener: Automatically triggers load & polling when OAuth completes
  useEffect(() => {
    const handleOAuthMessage = (event) => {
      if (event.origin === window.location.origin && event.data?.sentideskOAuth) {
        load({ quiet: true })
      }
    }
    window.addEventListener('message', handleOAuthMessage)
    return () => window.removeEventListener('message', handleOAuthMessage)
  }, [load])

  // Active Pacing Status Memo: Extract active progress string (e.g. "Analyzing message 3 of 9...")
  const activeAnalyzingStatus = useMemo(() => {
    if (!messages) return null
    const target = messages.find((m) => m.ai_status && m.ai_status.startsWith('Analyzing'))
    return target ? target.ai_status : null
  }, [messages])

  // Smart Polling Hook: Activates immediately after connection and polls GET /api/messages every 3 seconds
  // while any message has ai_status === "Pending", startsWith("Analyzing"), or category === "Pending"
  useEffect(() => {
    if (!messages || !messages.length) return

    const hasPending = messages.some(
      (m) =>
        m.ai_status === 'Pending' ||
        m.category === 'Pending' ||
        (m.ai_status && m.ai_status.startsWith('Analyzing')) ||
        (!m.analysis && m.ai_status !== 'Completed' && m.ai_status !== 'Failed' && m.ai_status !== 'Rate Limited')
    )

    if (!hasPending) {
      return // Automatically clear & stop polling when all messages are fully categorized
    }

    const intervalId = setInterval(async () => {
      try {
        const { data } = await api.get('/api/messages', { params: { provider } })
        if (data && data.messages) {
          // Seamless state update without layout shift or full page reload
          setMessages(data.messages)
        }
      } catch (err) {
        console.error('Smart polling error:', err)
      }
    }, 3000)

    return () => clearInterval(intervalId)
  }, [messages, provider])

  const sorted = useMemo(
    () =>
      [...(messages || [])].sort(
        (a, b) => new Date(b.timestamp || 0) - new Date(a.timestamp || 0)
      ),
    [messages]
  )

  // Summary counts
  const threatCount = useMemo(() => {
    return sorted.filter((m) => {
      const sec = m.analysis?.security || {}
      return sec.suspicious_url || sec.suspicious_email || sec.threat_type !== 'none' || sec.risk_level === 'Critical' || sec.risk_level === 'High'
    }).length
  }, [sorted])

  const resolvedCount = useMemo(() => {
    return sorted.filter((m) => m.analysis?.resolution_status?.toLowerCase() === 'resolved').length
  }, [sorted])

  const unresolvedCount = sorted.length - resolvedCount

  // Filtered messages list
  const filtered = useMemo(() => {
    return sorted.filter((m) => {
      const q = query.toLowerCase()
      const s = (m.sender || '').toLowerCase()
      const subj = (m.subject || '').toLowerCase()
      const content = (m.content || '').toLowerCase()
      const issue = (m.analysis?.issue_keyphrase || '').toLowerCase()
      const cat = (m.category || m.analysis?.category || '').toLowerCase()
      const sec = m.analysis?.security || {}
      const resStatus = (m.analysis?.resolution_status || m.status || 'Unresolved').toLowerCase()

      const matchesQuery = !q || s.includes(q) || subj.includes(q) || content.includes(q) || issue.includes(q) || cat.includes(q)

      const isPending = m.ai_status === 'Pending' || m.category === 'Pending' || (!m.analysis && m.ai_status !== 'Completed')

      let matchesFilter = true
      if (quickFilter === 'threats') {
        matchesFilter = !isPending && (sec.suspicious_url || sec.suspicious_email || (sec.threat_type && sec.threat_type !== 'none') || sec.risk_level === 'Critical' || sec.risk_level === 'High')
      } else if (quickFilter === 'support') {
        matchesFilter = isPending || (!sec.suspicious_url && !sec.suspicious_email && (!sec.threat_type || sec.threat_type === 'none'))
      } else if (quickFilter === 'unresolved') {
        matchesFilter = isPending || resStatus === 'unresolved'
      } else if (quickFilter === 'resolved') {
        matchesFilter = !isPending && resStatus === 'resolved'
      }

      return matchesQuery && matchesFilter
    })
  }, [sorted, query, quickFilter])

  if (loading) return <Loading />

  return (
    <>
      {/* Top Channel Navigation Bar */}
      <div className="mb-6 flex flex-wrap items-center gap-2 border-b border-slate-200 pb-3">
        {Object.entries(providers).map(([key, item]) => {
          const Icon = item.icon
          const active = key === provider
          return (
            <NavLink
              key={key}
              to={`/connections/${key}`}
              className={`flex items-center gap-2 rounded-xl px-4 py-2 text-sm font-bold transition ${
                active
                  ? 'bg-indigo-600 text-white shadow-sm'
                  : 'bg-white text-slate-600 hover:bg-slate-100 border border-slate-200'
              }`}
            >
              <Icon size={16} />
              {item.name}
            </NavLink>
          )
        })}
      </div>

      {/* Header & Controls */}
      <div className="mb-6 flex flex-wrap items-start justify-between gap-4">
        <div>
          <div className="flex flex-wrap items-center gap-2.5">
            <h1 className="text-2xl font-black text-slate-900">{meta.name}</h1>
            {meta.isUnderConstruction ? (
              <span className="inline-flex items-center gap-1.5 rounded-full bg-amber-100 px-3 py-1 text-xs font-bold text-amber-800 border border-amber-300">
                <Wrench size={13} /> Under Construction
              </span>
            ) : (
              status?.status === 'connected' && (
                <span className="inline-flex items-center gap-1.5 rounded-full bg-emerald-50 px-3 py-1 text-xs font-bold text-emerald-700 border border-emerald-200">
                  <span className="h-2 w-2 rounded-full bg-emerald-500 animate-pulse" />
                  Connected {status.connected_email ? `(${status.connected_email})` : ''}
                </span>
              )
            )}
          </div>
          <p className="mt-1 text-sm text-slate-500">{meta.description}</p>
        </div>

        {!meta.isUnderConstruction && (
          <button
            onClick={sync}
            className="btn-primary flex items-center gap-2 bg-indigo-600 text-white hover:bg-indigo-700 shadow-md cursor-pointer"
            disabled={status?.status !== 'connected' || syncing}
          >
            <RefreshCw size={16} className={syncing ? 'animate-spin' : ''} />
            {syncing ? 'Syncing DB…' : 'Refresh Inbox'}
          </button>
        )}
      </div>

      {/* SUMMARY STRIP WITH COLORED PILLS */}
      {!meta.isUnderConstruction && status?.status === 'connected' && (
        <div className="mb-6 grid grid-cols-2 sm:grid-cols-4 gap-3">
          <div className="rounded-xl border border-indigo-200 bg-indigo-50/70 p-3.5 flex items-center justify-between">
            <span className="text-xs font-bold text-indigo-900">
              {provider === 'whatsapp' ? 'Total WhatsApp Msgs' : provider === 'instagram' ? 'Total Instagram DMs' : 'Total Emails'}
            </span>
            <span className="rounded-full bg-indigo-600 px-2.5 py-0.5 text-xs font-black text-white">{sorted.length}</span>
          </div>

          <div className="rounded-xl border border-rose-200 bg-rose-50/70 p-3.5 flex items-center justify-between">
            <span className="text-xs font-bold text-rose-900">Security Threats</span>
            <span className="rounded-full bg-rose-600 px-2.5 py-0.5 text-xs font-black text-white">{threatCount}</span>
          </div>

          <div className="rounded-xl border border-amber-200 bg-amber-50/70 p-3.5 flex items-center justify-between">
            <span className="text-xs font-bold text-amber-900">Unresolved Issues</span>
            <span className="rounded-full bg-amber-600 px-2.5 py-0.5 text-xs font-black text-white">{unresolvedCount}</span>
          </div>

          <div className="rounded-xl border border-emerald-200 bg-emerald-50/70 p-3.5 flex items-center justify-between">
            <span className="text-xs font-bold text-emerald-900">Resolved</span>
            <span className="rounded-full bg-emerald-600 px-2.5 py-0.5 text-xs font-black text-white">{resolvedCount}</span>
          </div>
        </div>
      )}

      {error && (
        <div className="mb-5 flex items-start gap-3 rounded-xl bg-rose-50 p-4 text-sm text-rose-700 border border-rose-200">
          <AlertTriangle size={18} className="mt-0.5 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {syncMessage && (
        <div className="mb-5 rounded-xl bg-emerald-50 p-4 text-sm text-emerald-700 border border-emerald-200 flex items-center gap-2">
          <CheckCircle2 size={18} className="text-emerald-600 shrink-0" />
          <span>{syncMessage}</span>
        </div>
      )}

      {/* API RATE LIMIT PACING PROGRESS BANNER */}
      {activeAnalyzingStatus && (
        <div className="mb-5 rounded-xl bg-amber-50 p-4 text-sm text-amber-900 border border-amber-300 flex items-center justify-between shadow-2xs animate-pulse">
          <div className="flex items-center gap-3">
            <RefreshCw size={18} className="text-amber-600 animate-spin shrink-0" />
            <div>
              <p className="font-bold text-amber-950">{activeAnalyzingStatus}</p>
              <p className="text-xs text-amber-700 mt-0.5">
                API rate-limit pacing active (~15s between requests to stay safely under Gemini 5 req/min quota).
              </p>
            </div>
          </div>
        </div>
      )}

      {/* WHATSAPP SEND MESSAGE CARD */}
      {provider === 'whatsapp' && (
        <div className="card mb-6 overflow-hidden border border-emerald-200 bg-white shadow-sm">
          <div className="border-b border-emerald-100 bg-emerald-50/60 px-5 py-4 flex items-center justify-between">
            <div className="flex items-center gap-2.5">
              <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-emerald-600 text-white font-bold">
                <MessageCircle size={18} />
              </div>
              <div>
                <h3 className="text-base font-black text-slate-900">Send WhatsApp Message</h3>
                <p className="text-xs text-slate-500">Dispatch outbound text via Meta WhatsApp Business Cloud API</p>
              </div>
            </div>
            <span className="text-xs font-semibold text-emerald-700 bg-emerald-100/80 px-2.5 py-1 rounded-full border border-emerald-200">
              Graph API v20.0
            </span>
          </div>

          <form onSubmit={handleSendWhatsApp} className="p-5">
            {waSendSuccess && (
              <div className="mb-4 flex items-center gap-2.5 rounded-xl bg-emerald-50 p-3.5 text-xs font-bold text-emerald-800 border border-emerald-200">
                <CheckCircle2 size={16} className="text-emerald-600 shrink-0" />
                <span>{waSendSuccess}</span>
              </div>
            )}

            {waSendError && (
              <div className="mb-4 flex items-start gap-2.5 rounded-xl bg-rose-50 p-3.5 text-xs font-medium text-rose-700 border border-rose-200">
                <AlertTriangle size={16} className="mt-0.5 shrink-0 text-rose-600" />
                <span>{waSendError}</span>
              </div>
            )}

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
              <div>
                <label className="block text-xs font-bold text-slate-700 mb-1">
                  Recipient Phone Number <span className="text-rose-500">*</span>
                </label>
                <input
                  type="text"
                  placeholder="e.g. +14155552671 or 14155552671"
                  value={waTo}
                  onChange={(e) => setWaTo(e.target.value)}
                  required
                  className="w-full rounded-xl border border-slate-200 bg-slate-50/50 py-2 px-3 text-xs outline-none focus:border-emerald-500 focus:bg-white font-mono"
                />
                <p className="mt-1 text-[11px] text-slate-400">Include country code without spaces or dashes</p>
              </div>

              <div className="md:col-span-2">
                <label className="block text-xs font-bold text-slate-700 mb-1">
                  Message Content <span className="text-rose-500">*</span>
                </label>
                <input
                  type="text"
                  placeholder="Type your WhatsApp support message body here..."
                  value={waMessage}
                  onChange={(e) => setWaMessage(e.target.value)}
                  required
                  className="w-full rounded-xl border border-slate-200 bg-slate-50/50 py-2 px-3 text-xs outline-none focus:border-emerald-500 focus:bg-white"
                />
              </div>
            </div>

            <div className="flex flex-wrap items-center justify-between gap-3 pt-2 border-t border-slate-100">
              <p className="text-[11px] text-slate-400 italic">
                Note: In Meta Sandbox mode, recipient phone number must be registered under Test Numbers in Meta Developer Portal.
              </p>
              <button
                type="submit"
                disabled={waSending || !waTo.trim() || !waMessage.trim()}
                className="btn-primary flex items-center gap-2 bg-emerald-600 hover:bg-emerald-700 text-white text-xs font-bold px-4 py-2 rounded-xl shadow-xs cursor-pointer disabled:opacity-50"
              >
                {waSending ? (
                  <>
                    <RefreshCw size={14} className="animate-spin" />
                    Sending via Meta API…
                  </>
                ) : (
                  <>
                    <Send size={14} />
                    Send WhatsApp Message
                  </>
                )}
              </button>
            </div>
          </form>
        </div>
      )}

      {/* FILTER TABS & SEARCH */}
      {!meta.isUnderConstruction && status?.status === 'connected' && (
        <div className="card overflow-hidden shadow-sm mb-6">
          <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-100 p-4 bg-slate-50/60">
            <div className="flex flex-wrap gap-1.5">
              {[
                { id: 'all', label: `All (${sorted.length})` },
                { id: 'threats', label: `Security Threats (${threatCount})` },
                { id: 'support', label: 'Support Inquiries' },
                { id: 'unresolved', label: `Unresolved (${unresolvedCount})` },
                { id: 'resolved', label: `Resolved (${resolvedCount})` },
              ].map(tab => (
                <button
                  key={tab.id}
                  onClick={() => setQuickFilter(tab.id)}
                  className={`rounded-xl px-3.5 py-1.5 text-xs font-bold transition-all cursor-pointer ${
                    quickFilter === tab.id
                      ? 'bg-indigo-600 text-white shadow-sm'
                      : 'bg-white text-slate-600 hover:bg-slate-100 border border-slate-200'
                  }`}
                >
                  {tab.label}
                </button>
              ))}
            </div>

            <div className="relative min-w-[220px] flex-1 sm:max-w-xs">
              <Search className="absolute left-3 top-2.5 text-slate-400" size={15} />
              <input
                type="text"
                placeholder={provider === 'whatsapp' ? 'Search WhatsApp messages or issues...' : provider === 'instagram' ? 'Search Instagram DMs...' : 'Search emails, subjects, or issues...'}
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                className="w-full rounded-xl border border-slate-200 bg-white py-1.5 pl-9 pr-3 text-xs outline-none focus:border-indigo-500"
              />
            </div>
          </div>

          {/* EMAIL CARDS WITH COMBINED INTELLIGENCE PANEL */}
          {filtered.length ? (
            <div className="divide-y divide-slate-100">
              {filtered.map((message, index) => {
                const senderInfo = parseSender(message.sender)
                const avatarStyle = getAvatarColor(senderInfo.name)
                const initial = (senderInfo.name[0] || 'M').toUpperCase()

                return (
                  <article key={index} className="p-6 transition-colors hover:bg-slate-50/40">
                    <div className="flex flex-wrap items-start justify-between gap-3 border-b border-slate-100 pb-3">
                      <div className="flex items-center gap-3">
                        <div className={`flex h-10 w-10 items-center justify-center rounded-full border text-sm font-black shadow-2xs ${avatarStyle}`}>
                          {initial}
                        </div>
                        <div>
                          <div className="flex items-center gap-2">
                            <span className="font-bold text-slate-900 text-sm">{senderInfo.name}</span>
                            {senderInfo.email && <span className="text-xs text-slate-400">&lt;{senderInfo.email}&gt;</span>}
                            {(message.ai_status === 'Pending' || (message.ai_status && message.ai_status.startsWith('Analyzing')) || (!message.analysis && message.ai_status !== 'Completed' && message.ai_status !== 'Failed' && message.ai_status !== 'Rate Limited')) && (
                              <span className="inline-flex items-center gap-1.5 rounded-full bg-amber-100 px-2.5 py-0.5 text-xs font-bold text-amber-800 border border-amber-300 shadow-2xs">
                                <RefreshCw size={12} className="animate-spin text-amber-700" />
                                {message.ai_status && message.ai_status.startsWith('Analyzing') ? message.ai_status.split('...')[0] : 'Analyzing...'}
                              </span>
                            )}
                          </div>
                          <span className="text-[11px] text-slate-400 font-medium">{formatDate(message.timestamp)}</span>
                        </div>
                      </div>

                      {/* RESOLUTION STATUS INTERACTIVE TOGGLE BUTTON */}
                      <button
                        onClick={() => handleToggleResolutionStatus(message)}
                        disabled={updatingStatusId === message.external_id}
                        className={`flex items-center gap-1.5 rounded-full px-3 py-1 text-xs font-bold transition shadow-2xs cursor-pointer border ${
                          (message.analysis?.resolution_status || message.status || 'Unresolved').toLowerCase() === 'resolved'
                            ? 'bg-emerald-50 text-emerald-800 hover:bg-emerald-100 border-emerald-300'
                            : 'bg-amber-50 text-amber-900 hover:bg-amber-100 border-amber-300'
                        }`}
                        title="Click to toggle resolution status between Resolved and Unresolved"
                      >
                        {updatingStatusId === message.external_id ? (
                          <RefreshCw size={13} className="animate-spin text-slate-600" />
                        ) : (message.analysis?.resolution_status || message.status || 'Unresolved').toLowerCase() === 'resolved' ? (
                          <>
                            <CheckCircle2 size={13} className="text-emerald-600" />
                            <span>Resolved</span>
                          </>
                        ) : (
                          <>
                            <Clock3 size={13} className="text-amber-600" />
                            <span>Unresolved</span>
                          </>
                        )}
                      </button>
                    </div>

                    {message.subject && (
                      <h3 className="mt-3 text-base font-bold text-slate-900 font-sans leading-snug">
                        {message.subject}
                      </h3>
                    )}

                    <FormattedContent text={message.content} />

                    {/* COMBINED INTELLIGENCE TWO-PANEL COMPONENT */}
                    <div className="mt-4">
                      <CombinedIntelligencePanel
                        analysis={message.analysis}
                        text={message.content}
                        conversationId={message.external_id || `MSG-${index + 100}`}
                        aiStatus={message.ai_status}
                        onToggleStatus={(newStatus) => handleToggleResolutionStatus(message)}
                        isUpdatingStatus={updatingStatusId === message.external_id}
                      />
                    </div>
                  </article>
                )
              })}
            </div>
          ) : (
            <div className="p-12 text-center text-slate-400">
              <Inbox size={32} className="mx-auto mb-2 opacity-50" />
              <p className="font-bold text-slate-600">
                No {provider === 'whatsapp' ? 'WhatsApp messages' : provider === 'instagram' ? 'Instagram DMs' : 'emails'} match the selected filter
              </p>
            </div>
          )}
        </div>
      )}
    </>
  )
}
