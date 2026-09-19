import { useEffect, useMemo, useState } from 'react'
import {
  Search, ShieldAlert, ShieldCheck, Tag, MessageSquare, X, Eye,
  User, CheckCircle2, Clock, AlertTriangle, ArrowRight
} from 'lucide-react'
import api from '../api'
import Loading from '../components/Loading'
import Badge from '../components/Badge'
import CombinedIntelligencePanel from '../components/CombinedIntelligencePanel'

const avatarColors = [
  'bg-indigo-100 text-indigo-700 border-indigo-200',
  'bg-emerald-100 text-emerald-700 border-emerald-200',
  'bg-violet-100 text-violet-700 border-violet-200',
  'bg-amber-100 text-amber-700 border-amber-200',
  'bg-rose-100 text-rose-700 border-rose-200',
]

function getAvatarColor(name) {
  let hash = 0
  for (let i = 0; i < (name || '').length; i++) {
    hash = (hash << 5) - hash + name.charCodeAt(i)
  }
  return avatarColors[Math.abs(hash) % avatarColors.length]
}

export default function Conversations() {
  const [items, setItems] = useState(null)
  const [query, setQuery] = useState('')
  const [filterTab, setFilterTab] = useState('all') // 'all' | 'threats' | 'support' | 'unresolved' | 'resolved'
  const [selectedConv, setSelectedConv] = useState(null)

  useEffect(() => {
    api.get('/conversations')
      .then(r => setItems(r.data))
      .catch(() => setItems([]))
  }, [])

  const filtered = useMemo(() => {
    return (items || []).filter(c => {
      const q = query.toLowerCase()
      const name = (c.customer_name || '').toLowerCase()
      const email = (c.email || '').toLowerCase()
      const text = c.messages?.map(m => m.content).join(' ').toLowerCase() || ''
      const sec = c.analysis?.security || {}
      const resStatus = (c.analysis?.resolution_status || c.status || 'open').toLowerCase()

      const matchesQuery = !q || name.includes(q) || email.includes(q) || text.includes(q)

      let matchesFilter = true
      if (filterTab === 'threats') {
        matchesFilter = sec.suspicious_url || sec.suspicious_email || sec.threat_type !== 'none' || sec.risk_level === 'Critical' || sec.risk_level === 'High'
      } else if (filterTab === 'support') {
        matchesFilter = !sec.suspicious_url && !sec.suspicious_email && sec.threat_type === 'none'
      } else if (filterTab === 'unresolved') {
        matchesFilter = resStatus === 'unresolved' || c.status === 'open'
      } else if (filterTab === 'resolved') {
        matchesFilter = resStatus === 'resolved' || c.status === 'resolved'
      }

      return matchesQuery && matchesFilter
    })
  }, [items, query, filterTab])

  if (!items) return <Loading />

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-2xl font-black text-slate-900">Conversations List</h1>
          <p className="mt-1 text-sm text-slate-500">
            Unified view of customer support tickets and security-analyzed email threads.
          </p>
        </div>
      </div>

      {/* FILTER TABS & SEARCH */}
      <div className="card overflow-hidden shadow-sm">
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-100 p-4 bg-slate-50/60">
          <div className="flex flex-wrap gap-1.5">
            {[
              { id: 'all', label: `All Conversations (${items.length})` },
              { id: 'threats', label: 'Security Threats' },
              { id: 'support', label: 'Support Inquiries' },
              { id: 'unresolved', label: 'Unresolved' },
              { id: 'resolved', label: 'Resolved' },
            ].map(tab => (
              <button
                key={tab.id}
                onClick={() => setFilterTab(tab.id)}
                className={`rounded-xl px-3.5 py-1.5 text-xs font-bold transition-all cursor-pointer ${
                  filterTab === tab.id
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
              placeholder="Search customers or messages..."
              value={query}
              onChange={e => setQuery(e.target.value)}
              className="w-full rounded-xl border border-slate-200 bg-white py-1.5 pl-9 pr-3 text-xs outline-none focus:border-indigo-500"
            />
          </div>
        </div>

        {/* CONVERSATIONS TABLE */}
        <div className="overflow-x-auto">
          <table className="w-full min-w-[750px] text-left text-xs">
            <thead className="bg-slate-100/70 text-[10px] uppercase font-bold text-slate-500 tracking-wider">
              <tr>
                <th className="px-5 py-3.5">Customer / Contact</th>
                <th className="px-5 py-3.5">Risk Level</th>
                <th className="px-5 py-3.5">Category</th>
                <th className="px-5 py-3.5">Sentiment</th>
                <th className="px-5 py-3.5">Status</th>
                <th className="px-5 py-3.5">Priority</th>
                <th className="px-5 py-3.5 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 font-sans">
              {filtered.map(c => {
                const initial = (c.customer_name?.[0] || 'C').toUpperCase()
                const avatarStyle = getAvatarColor(c.customer_name)
                const sec = c.analysis?.security || {}
                const risk = (sec.risk_level || c.priority || 'low').toLowerCase()
                const sentiment = (c.analysis?.sentiment || 'neutral').toLowerCase()
                const category = c.analysis?.category || 'Support Inquiry'

                const riskBadgeStyles = {
                  critical: 'bg-rose-100 text-rose-800 border-rose-200',
                  high: 'bg-orange-100 text-orange-800 border-orange-200',
                  medium: 'bg-amber-100 text-amber-800 border-amber-200',
                  low: 'bg-emerald-100 text-emerald-800 border-emerald-200',
                }

                return (
                  <tr key={c.id} className="hover:bg-slate-50/80 transition-colors">
                    <td className="px-5 py-4">
                      <div className="flex items-center gap-3">
                        <div className={`flex h-9 w-9 items-center justify-center rounded-full border text-xs font-black shrink-0 ${avatarStyle}`}>
                          {initial}
                        </div>
                        <div>
                          <div className="font-bold text-slate-900 text-xs">{c.customer_name}</div>
                          <div className="text-[11px] text-slate-400 truncate max-w-[180px]">{c.email || 'No email'}</div>
                        </div>
                      </div>
                    </td>

                    <td className="px-5 py-4">
                      <span className={`inline-flex items-center gap-1 rounded-full px-2.5 py-0.5 text-[10px] font-black capitalize border ${riskBadgeStyles[risk] || riskBadgeStyles.low}`}>
                        {risk === 'critical' || risk === 'high' ? <ShieldAlert size={11} /> : <ShieldCheck size={11} />}
                        {risk}
                      </span>
                    </td>

                    <td className="px-5 py-4 font-semibold text-slate-700">
                      <span className="rounded-md bg-slate-100 px-2 py-1 border border-slate-200">
                        {category}
                      </span>
                    </td>

                    <td className="px-5 py-4 capitalize font-semibold">
                      <span className={`rounded-md px-2 py-0.5 text-[11px] ${sentiment === 'positive' ? 'text-emerald-700 bg-emerald-50' : sentiment === 'negative' ? 'text-rose-700 bg-rose-50' : 'text-slate-600 bg-slate-100'}`}>
                        {sentiment}
                      </span>
                    </td>

                    <td className="px-5 py-4">
                      <Badge value={c.status} />
                    </td>

                    <td className="px-5 py-4">
                      <Badge value={c.priority} />
                    </td>

                    <td className="px-5 py-4 text-right">
                      <button
                        onClick={() => setSelectedConv(c)}
                        className="inline-flex items-center gap-1 rounded-xl bg-indigo-50 border border-indigo-200 px-3 py-1.5 font-bold text-indigo-700 hover:bg-indigo-600 hover:text-white transition-all cursor-pointer"
                      >
                        <Eye size={13} /> View Analysis
                      </button>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>

          {!filtered.length && (
            <div className="p-10 text-center text-slate-400 font-medium">
              No conversations found matching filter.
            </div>
          )}
        </div>
      </div>

      {/* CONVERSATION DETAIL MODAL (CANONICAL FORMAT) */}
      {selectedConv && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/60 p-4 backdrop-blur-xs animate-fadeIn">
          <div className="relative w-full max-w-3xl max-h-[90vh] overflow-y-auto rounded-3xl bg-white p-6 shadow-2xl space-y-6">
            <div className="flex items-center justify-between border-b pb-4">
              <div>
                <span className="text-[10px] font-black uppercase tracking-wider text-indigo-600 bg-indigo-50 px-2.5 py-1 rounded-md">
                  Canonical Conversation Output
                </span>
                <h2 className="mt-1 text-xl font-black text-slate-900">{selectedConv.customer_name}</h2>
                <p className="text-xs text-slate-400">{selectedConv.email}</p>
              </div>

              <button
                onClick={() => setSelectedConv(null)}
                className="rounded-full bg-slate-100 p-2 text-slate-400 hover:bg-slate-200 hover:text-slate-700 cursor-pointer"
              >
                <X size={18} />
              </button>
            </div>

            {/* MESSAGE HISTORY THREAD */}
            {selectedConv.messages?.length > 0 && (
              <div className="space-y-3 rounded-2xl bg-slate-50 p-4 border border-slate-200">
                <span className="text-xs font-bold text-slate-500 flex items-center gap-1.5">
                  <MessageSquare size={14} className="text-indigo-600" /> Conversation History ({selectedConv.messages.length} messages)
                </span>
                <div className="space-y-2 max-h-48 overflow-y-auto pr-1">
                  {selectedConv.messages.map((m, idx) => (
                    <div key={idx} className={`flex ${m.role === 'agent' ? 'justify-end' : 'justify-start'}`}>
                      <div className={`max-w-[85%] rounded-2xl p-3 text-xs ${m.role === 'agent' ? 'bg-indigo-600 text-white' : 'bg-white text-slate-800 border border-slate-200 shadow-2xs'}`}>
                        <div className="font-bold opacity-80 text-[10px] uppercase mb-0.5">{m.role}</div>
                        <p className="leading-relaxed whitespace-pre-wrap">{m.content}</p>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* COMBINED INTELLIGENCE COMPONENT */}
            <CombinedIntelligencePanel
              analysis={selectedConv.analysis}
              text={selectedConv.messages?.map(m => m.content).join(' ')}
              conversationId={selectedConv.id}
            />
          </div>
        </div>
      )}
    </div>
  )
}
