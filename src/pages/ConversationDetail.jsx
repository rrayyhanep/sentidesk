import { useEffect, useState } from 'react'
import { ArrowLeft, Send, MessageSquare } from 'lucide-react'
import { Link, useParams } from 'react-router-dom'
import api from '../api'
import Loading from '../components/Loading'
import Badge from '../components/Badge'
import CombinedIntelligencePanel from '../components/CombinedIntelligencePanel'

export default function ConversationDetail() {
  const { id } = useParams()
  const [conversation, setConversation] = useState(null)
  const [text, setText] = useState('')
  const [error, setError] = useState('')

  useEffect(() => {
    api.get(`/conversations/${id}`)
      .then(r => setConversation(r.data))
      .catch(e => setError(e.response?.data?.detail || 'Conversation not found.'))
  }, [id])

  const send = async e => {
    e.preventDefault()
    if (!text.trim()) return
    try {
      const { data } = await api.post(`/conversations/${id}/messages`, { role: 'agent', content: text })
      setConversation(data)
      setText('')
    } catch {
      setError('Message could not be sent.')
    }
  }

  if (!conversation && !error) return <Loading />
  if (error) return <div className="rounded-xl bg-rose-50 p-5 text-sm font-bold text-rose-600 border border-rose-200">{error}</div>

  const fullText = conversation.messages?.map(m => m.content).join(' ') || ''

  return (
    <div className="space-y-6">
      <Link to="/conversations" className="inline-flex items-center gap-2 text-xs font-bold text-slate-500 hover:text-indigo-600 transition-colors">
        <ArrowLeft size={16} /> Back to conversations
      </Link>

      <div className="grid gap-6 lg:grid-cols-3">
        {/* MESSAGES THREAD & REPLY PANEL */}
        <section className="card lg:col-span-2 shadow-sm border border-slate-200 overflow-hidden">
          <div className="flex items-start justify-between border-b p-5 bg-slate-50/60">
            <div>
              <h1 className="text-xl font-black text-slate-900">{conversation.customer_name}</h1>
              <p className="mt-0.5 text-xs text-slate-500">{conversation.email || 'No email provided'}</p>
            </div>
            <div className="flex gap-2">
              <Badge value={conversation.status} />
              <Badge value={conversation.priority} />
            </div>
          </div>

          <div className="space-y-3.5 p-5 min-h-[250px] max-h-[450px] overflow-y-auto">
            {conversation.messages?.map((m, i) => (
              <div key={i} className={`flex ${m.role === 'agent' ? 'justify-end' : 'justify-start'}`}>
                <div className={`max-w-[85%] rounded-2xl px-4 py-3 text-xs leading-relaxed ${m.role === 'agent' ? 'bg-indigo-600 text-white shadow-sm' : 'bg-slate-100 text-slate-800 border border-slate-200'}`}>
                  <p className="font-bold opacity-75 text-[10px] uppercase">{m.role}</p>
                  <p className="mt-1 whitespace-pre-wrap">{m.content}</p>
                  <p className="mt-2 text-[10px] opacity-60">
                    {m.timestamp && new Date(m.timestamp).toLocaleString()}
                  </p>
                </div>
              </div>
            ))}
          </div>

          <form onSubmit={send} className="flex gap-2 border-t p-4 bg-white">
            <input
              value={text}
              onChange={e => setText(e.target.value)}
              placeholder="Write a support reply..."
              className="flex-1 rounded-xl border border-slate-200 px-4 py-2.5 text-xs outline-none focus:border-indigo-500"
            />
            <button className="btn-primary flex items-center gap-2 bg-indigo-600 text-white px-4 py-2.5 text-xs font-bold rounded-xl hover:bg-indigo-700 cursor-pointer">
              <Send size={15} /> Send Reply
            </button>
          </form>
        </section>

        {/* SIDEBAR METADATA */}
        <aside className="card h-fit p-5 border border-slate-200 shadow-sm space-y-4">
          <h2 className="font-bold text-slate-900 text-sm border-b pb-2">Conversation Metadata</h2>
          <dl className="space-y-3 text-xs">
            <div>
              <dt className="text-slate-400 font-medium">Conversation ID</dt>
              <dd className="mt-0.5 font-mono font-bold text-slate-800 bg-slate-100 p-1.5 rounded-md truncate">{conversation.id}</dd>
            </div>
            <div>
              <dt className="text-slate-400 font-medium">Customer Name</dt>
              <dd className="mt-0.5 font-bold text-slate-800">{conversation.customer_name}</dd>
            </div>
            <div>
              <dt className="text-slate-400 font-medium">Channel Source</dt>
              <dd className="mt-0.5 font-bold capitalize text-indigo-700">{conversation.source || 'Email'}</dd>
            </div>
          </dl>
        </aside>
      </div>

      {/* COMBINED INTELLIGENCE PANEL */}
      <div className="card p-6 border border-slate-200 shadow-sm">
        <h2 className="text-lg font-black text-slate-900 mb-4 flex items-center gap-2">
          <MessageSquare size={18} className="text-indigo-600" /> Full Conversation Intelligence Analysis
        </h2>
        <CombinedIntelligencePanel
          analysis={conversation.analysis}
          text={fullText}
          conversationId={conversation.id}
        />
      </div>
    </div>
  )
}
