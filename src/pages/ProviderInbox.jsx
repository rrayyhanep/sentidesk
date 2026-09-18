import { useEffect, useMemo, useState } from 'react'
import { AlertTriangle, Inbox, RefreshCw, ShieldCheck } from 'lucide-react'
import { useParams } from 'react-router-dom'
import api from '../api'
import Loading from '../components/Loading'
import Badge from '../components/Badge'

const providers = {
  gmail: { name: 'Gmail', description: 'Review messages imported from your Gmail inbox.' },
  whatsapp: { name: 'WhatsApp', description: 'Review customer messages from WhatsApp.' },
  instagram: { name: 'Instagram', description: 'Review customer messages and replies from Instagram.' },
}

export default function ProviderInbox() {
  const { provider } = useParams()
  const meta = providers[provider] || { name: provider, description: 'Provider inbox' }
  const [status, setStatus] = useState(null); const [messages, setMessages] = useState(null); const [error, setError] = useState('')
  const load = async () => {
    setError(''); setMessages(null)
    try {
      const connection = await api.get(`/connections/${provider}/status`)
      setStatus(connection.data)
      if (connection.data.status !== 'connected') return
      const { data } = await api.get(`/connections/${provider}/inbox`)
      setMessages(data.messages || [])
    } catch (err) { setError(err.response?.data?.detail || `Could not load ${meta.name} inbox.`) }
  }
  useEffect(() => { load() }, [provider])
  const sorted = useMemo(() => [...(messages || [])].sort((a, b) => new Date(b.timestamp || 0) - new Date(a.timestamp || 0)), [messages])
  return <><div className="mb-7 flex flex-wrap items-start justify-between gap-3"><div><h1 className="text-2xl font-black">{meta.name} inbox</h1><p className="mt-1 text-slate-500">{meta.description}</p></div><button onClick={load} className="btn-ghost flex items-center gap-2" disabled={!status}><RefreshCw size={16}/> Refresh</button></div>
    {error && <div className="mb-5 flex gap-3 rounded-xl bg-rose-50 p-4 text-sm text-rose-700"><AlertTriangle size={18}/><span>{error}</span></div>}
    {!status && !error && <Loading />}
    {status && status.status !== 'connected' && <div className="card mx-auto max-w-xl p-8 text-center"><ShieldCheck className="mx-auto text-indigo-600" size={34}/><h2 className="mt-4 text-xl font-bold">Connect {meta.name} to get started</h2><p className="mt-2 text-sm leading-6 text-slate-500">{status.message || `This ${meta.name} inbox is not connected yet.`} Return to Connections to complete setup.</p></div>}
    {status?.status === 'connected' && !messages && !error && <Loading text={`Loading ${meta.name} messages…`} />}
    {status?.status === 'connected' && messages && <div className="card overflow-hidden"><div className="flex items-center justify-between border-b px-5 py-4"><div className="flex items-center gap-2 font-bold"><Inbox size={18} className="text-indigo-600"/> Imported messages</div><span className="text-sm text-slate-400">{messages.length} messages</span></div>{sorted.length ? <div className="divide-y">{sorted.map((message, index) => <div key={message.external_id || `${message.timestamp}-${index}`} className="p-5"><div className="flex flex-wrap items-center justify-between gap-2"><p className="font-bold text-slate-800">{message.sender}</p><span className="text-xs text-slate-400">{message.timestamp ? new Date(message.timestamp).toLocaleString() : 'No timestamp'}</span></div><p className="mt-2 whitespace-pre-wrap text-sm leading-6 text-slate-600">{message.content}</p>{message.analysis?.risk?.risk_level && <div className="mt-3"><Badge value={message.analysis.risk.risk_level}/></div>}</div>)}</div> : <div className="p-12 text-center text-slate-500">No messages have been imported from {meta.name} yet.</div>}</div>}
  </>
}
