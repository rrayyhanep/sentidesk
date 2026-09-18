import { useState } from 'react'
import { useParams } from 'react-router-dom'
import api from '../api'
import Badge from '../components/Badge'

const categories = {
  sentiment: { title: 'Sentiment analysis', description: 'Understand the emotional tone of a customer message.', endpoint: '/analyze/sentiment', key: 'sentiment' },
  phishing: { title: 'Phishing detection', description: 'Check a message for suspicious links and social engineering signals.', endpoint: '/analyze/phishing', key: 'phishing' },
  overview: { title: 'Message analysis', description: 'Run a complete safety and sentiment analysis on any message.', endpoint: '/analyze', key: null }
}
export default function CategoryPage() {
  const { type = 'overview' } = useParams(); const category = categories[type] || categories.overview
  const [text, setText] = useState(''); const [result, setResult] = useState(null); const [error, setError] = useState(''); const [busy, setBusy] = useState(false)
  const analyze = async e => { e.preventDefault(); if (!text.trim()) return; setBusy(true); setError(''); try { const { data } = await api.post(category.endpoint, { text }); setResult(data) } catch (err) { setError(err.response?.data?.detail || 'Analysis failed. Please try again.') } finally { setBusy(false) } }
  return <div className="mx-auto max-w-3xl"><div className="mb-8"><h1 className="text-2xl font-black">{category.title}</h1><p className="mt-1 text-slate-500">{category.description}</p></div><form onSubmit={analyze} className="card p-5"><textarea rows="7" value={text} onChange={e => setText(e.target.value)} placeholder="Paste a customer message here…" className="w-full resize-none rounded-xl border p-4 outline-none focus:border-indigo-500" /><div className="mt-4 flex justify-end"><button disabled={busy || !text.trim()} className="btn-primary">{busy ? 'Analyzing…' : 'Analyze message'}</button></div></form>{error && <div className="mt-5 rounded-xl bg-rose-50 p-4 text-sm text-rose-600">{error}</div>}{result && <div className="card mt-5 p-5"><h2 className="mb-4 font-bold">Analysis result</h2><div className="flex flex-wrap gap-3">{result.risk?.risk_level && <Badge value={result.risk.risk_level}/>} {result.sentiment?.label && <Badge value={result.sentiment.label}/>} {result.phishing?.is_phishing && <Badge value="high"/>}</div><pre className="mt-5 overflow-auto rounded-xl bg-slate-50 p-4 text-xs text-slate-600">{JSON.stringify(result, null, 2)}</pre></div>}</div>
}
