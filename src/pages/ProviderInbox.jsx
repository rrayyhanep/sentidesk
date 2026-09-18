import { useCallback, useEffect, useMemo, useState } from 'react'
import { AlertTriangle, Clock3, Inbox, RefreshCw, ShieldCheck, Sparkles } from 'lucide-react'
import { Link, useParams } from 'react-router-dom'
import api from '../api'
import Loading from '../components/Loading'
import Badge from '../components/Badge'

const providers = {
  gmail: { name: 'Gmail', description: 'Review messages imported from your Gmail inbox.', syncLabel: 'Sync inbox' },
  whatsapp: { name: 'WhatsApp', description: 'Review customer messages delivered by the WhatsApp Cloud API.', syncLabel: 'Check for messages' },
  instagram: { name: 'Instagram', description: 'Review customer messages delivered by Instagram webhooks.', syncLabel: 'Check for messages' },
}

const errorText = (err, fallback) => err.response?.data?.detail || fallback

async function withAnalysis(messages) {
  if (!messages.length) return messages
  const pending = messages.filter(message => !message.analysis)
  if (!pending.length) return messages
  try {
    const { data } = await api.post('/analyze/bulk', {
      messages: pending.map(message => ({ role: 'customer', content: message.content, timestamp: message.timestamp })),
    })
    let index = 0
    return messages.map(message => message.analysis ? message : { ...message, analysis: data[index++]?.analysis })
  } catch {
    return messages
  }
}

function Analysis({ analysis }) {
  if (!analysis) return <p className="mt-3 flex items-center gap-1.5 text-xs text-slate-400"><Sparkles size={13} /> Analysis unavailable</p>
  const risk = analysis.risk?.risk_level || analysis.risk_level
  const sentiment = analysis.sentiment?.label || analysis.sentiment
  return <div className="mt-4 flex flex-wrap items-center gap-2 border-t border-slate-100 pt-3">
    {analysis.category && <span className="rounded-full bg-indigo-50 px-2.5 py-1 text-xs font-semibold text-indigo-700">{analysis.category}</span>}
    {risk && <Badge value={risk} />}
    {sentiment && <span className="rounded-full bg-slate-100 px-2.5 py-1 text-xs font-semibold capitalize text-slate-600">{sentiment} sentiment</span>}
    {analysis.summary && <span className="basis-full text-xs text-slate-500">{analysis.summary}</span>}
  </div>
}

export default function ProviderInbox() {
  const { provider } = useParams()
  const meta = providers[provider] || { name: provider, description: 'Provider inbox.', syncLabel: 'Sync inbox' }
  const [status, setStatus] = useState(null)
  const [messages, setMessages] = useState(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(true)
  const [syncing, setSyncing] = useState(false)
  const [syncMessage, setSyncMessage] = useState('')

  const load = useCallback(async ({ quiet = false } = {}) => {
    if (!quiet) setLoading(true)
    setError('')
    try {
      const { data: connection } = await api.get(`/connections/${provider}/status`)
      setStatus(connection)
      if (connection.status !== 'connected') { setMessages(null); return }
      const { data } = await api.get(`/connections/${provider}/inbox`)
      setMessages(await withAnalysis(data.messages || []))
    } catch (err) {
      setError(errorText(err, `Could not load ${meta.name} inbox.`))
    } finally { setLoading(false) }
  }, [provider, meta.name])

  const sync = async () => {
    setSyncing(true); setSyncMessage(''); setError('')
    try {
      const { data } = await api.post(`/connections/${provider}/inbox/sync`)
      setSyncMessage(data.message || (data.status === 'synced' ? `Imported ${data.count || 0} messages.` : 'Inbox checked.'))
      setMessages(await withAnalysis(data.messages || []))
      await load({ quiet: true })
    } catch (err) { setError(errorText(err, `Could not sync ${meta.name} inbox.`)) }
    finally { setSyncing(false) }
  }

  useEffect(() => { load() }, [load])
  const sorted = useMemo(() => [...(messages || [])].sort((a, b) => new Date(b.timestamp || 0) - new Date(a.timestamp || 0)), [messages])

  return <><div className="mb-7 flex flex-wrap items-start justify-between gap-3"><div><div className="flex items-center gap-3"><h1 className="text-2xl font-black">{meta.name} inbox</h1>{status?.status === 'connected' && <span className="flex items-center gap-1 text-xs font-bold text-emerald-600"><span className="h-2 w-2 rounded-full bg-emerald-500" /> Connected</span>}</div><p className="mt-1 text-slate-500">{meta.description}</p></div><div className="flex gap-2"><button onClick={() => load()} className="btn-ghost flex items-center gap-2" disabled={loading || syncing}><RefreshCw size={16} className={loading ? 'animate-spin' : ''} /> Refresh</button><button onClick={sync} className="btn-primary flex items-center gap-2" disabled={status?.status !== 'connected' || syncing}>{syncing ? <RefreshCw size={16} className="animate-spin" /> : <RefreshCw size={16} />} {syncing ? 'Checking…' : meta.syncLabel}</button></div></div>
    {error && <div className="mb-5 flex items-start gap-3 rounded-xl bg-rose-50 p-4 text-sm text-rose-700"><AlertTriangle size={18} className="mt-0.5 shrink-0" /><span>{error}</span></div>}
    {syncMessage && <div className="mb-5 rounded-xl bg-emerald-50 p-4 text-sm text-emerald-700">{syncMessage}</div>}
    {loading && !status && <Loading />}
    {status && status.status !== 'connected' && <div className="card mx-auto max-w-xl p-8 text-center"><ShieldCheck className="mx-auto text-indigo-600" size={34} /><h2 className="mt-4 text-xl font-bold">Connect {meta.name} to get started</h2><p className="mt-2 text-sm leading-6 text-slate-500">{status.message || `This ${meta.name} inbox is not connected yet.`}</p><Link to="/connections" className="btn-primary mt-5 inline-flex">Open Connections</Link></div>}
    {status?.status === 'connected' && !messages && loading && <Loading text={`Loading ${meta.name} messages…`} />}
    {status?.status === 'connected' && messages && <div className="card overflow-hidden"><div className="flex flex-wrap items-center justify-between gap-2 border-b px-5 py-4"><div className="flex items-center gap-2 font-bold"><Inbox size={18} className="text-indigo-600" /> Imported messages</div><span className="text-sm text-slate-400">{messages.length} messages</span></div>{sorted.length ? <div className="divide-y">{sorted.map((message, index) => <article key={message.external_id || `${message.timestamp}-${index}`} className="p-5"><div className="flex flex-wrap items-center justify-between gap-2"><p className="font-bold text-slate-800">{message.sender}</p><span className="flex items-center gap-1 text-xs text-slate-400"><Clock3 size={13} />{message.timestamp ? new Date(message.timestamp).toLocaleString() : 'No timestamp'}</span></div>{message.subject && <p className="mt-1 text-sm font-semibold text-slate-600">{message.subject}</p>}<p className="mt-2 whitespace-pre-wrap text-sm leading-6 text-slate-600">{message.content}</p><Analysis analysis={message.analysis} /></article>)}</div> : <div className="p-12 text-center text-slate-500"><Inbox className="mx-auto mb-3 text-slate-300" size={30} />No messages have been imported from {meta.name} yet.</div>}</div>}
  </>
}
