import { useEffect, useState } from 'react'
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, Legend, AreaChart, Area
} from 'recharts'
import {
  AlertTriangle, CheckCircle2, Database, FileSearch, MessageSquare,
  ShieldAlert, ShieldCheck, Flame, Layers, Activity
} from 'lucide-react'
import api from '../api'
import Loading from '../components/Loading'

const fallbackStats = {
  total_conversations: 0,
  sentiment_breakdown: { positive: 0, neutral: 0, negative: 0 },
  top_categories: [],
  frequently_reported_issues: [],
  risk_breakdown: { critical: 0, high: 0, medium: 0, low: 0 },
  coverage: { summary: 0, risk: 0, phishing: 0, social_engineering: 0 },
  resolved_count: 0,
  unresolved_count: 0,
  critical_count: 0,
}

const ALL_CATEGORIES = [
  'Payment/Transaction Issue',
  'Account/Login Problem',
  'Product Issue',
  'Delivery/Shipping Problem',
  'Refund Request',
  'Subscription Issue',
  'Technical Problem',
  'Service Quality',
  'Billing Problem',
  'Security Concern',
  'Other',
]

const SENTIMENT_COLORS = {
  positive: '#10B981', // emerald
  neutral: '#64748B',  // slate
  negative: '#EF4444', // rose
}

const RISK_COLORS = {
  critical: '#EF4444',
  high: '#F97316',
  medium: '#F59E0B',
  low: '#10B981',
}

export default function Dashboard() {
  const [stats, setStats] = useState(null)
  const [error, setError] = useState('')

  useEffect(() => {
    api.get('/dashboard-stats')
      .then(r => setStats(r.data))
      .catch(e => setError(e.response?.data?.detail || 'Could not load dashboard stats.'))
  }, [])

  if (!stats && !error) return <Loading />

  const s = { ...fallbackStats, ...(stats || {}) }
  const total = s.total_conversations || 0
  const sentiments = s.sentiment_breakdown || {}
  const coverage = s.coverage || { summary: total, risk: total, phishing: 0, social_engineering: 0 }
  const risk = s.risk_breakdown || {}

  // Sentiment Pie Chart Data
  const pieData = [
    { name: 'Positive', value: sentiments.positive || 0, color: SENTIMENT_COLORS.positive },
    { name: 'Neutral', value: sentiments.neutral || 0, color: SENTIMENT_COLORS.neutral },
    { name: 'Negative', value: sentiments.negative || 0, color: SENTIMENT_COLORS.negative },
  ].filter(d => d.value > 0)

  // Category Distribution Bar Chart Data
  const categoryMap = new Map(ALL_CATEGORIES.map(c => [c, 0]))
  ;(s.top_categories || []).forEach(item => {
    categoryMap.set(item.name, item.count)
  })
  const categoryData = Array.from(categoryMap.entries()).map(([name, count]) => ({
    name: name.length > 18 ? name.substring(0, 16) + '…' : name,
    fullCategory: name,
    count,
  }))

  // Frequently Reported Issues Bar Chart Data
  const issueData = (s.frequently_reported_issues || []).slice(0, 6).map(item => ({
    issue: item.issue.length > 20 ? item.issue.substring(0, 18) + '…' : item.issue,
    fullIssue: item.issue,
    count: item.count,
  }))

  // Risk Breakdown Bar Chart Data
  const riskData = [
    { name: 'Critical', count: risk.critical || 0, fill: RISK_COLORS.critical },
    { name: 'High', count: risk.high || 0, fill: RISK_COLORS.high },
    { name: 'Medium', count: risk.medium || 0, fill: RISK_COLORS.medium },
    { name: 'Low', count: risk.low || 0, fill: RISK_COLORS.low },
  ]

  // Mock timeline data based on total count for complaint trends
  const trendData = [
    { date: 'Mon', complaints: Math.max(1, Math.round(total * 0.15)) },
    { date: 'Tue', complaints: Math.max(2, Math.round(total * 0.25)) },
    { date: 'Wed', complaints: Math.max(1, Math.round(total * 0.20)) },
    { date: 'Thu', complaints: Math.max(3, Math.round(total * 0.30)) },
    { date: 'Fri', complaints: Math.max(1, Math.round(total * 0.10)) },
  ]

  const mostCommonCategory = s.top_categories?.[0]?.name || 'None'
  const mostFrequentIssue = s.frequently_reported_issues?.[0]?.issue || 'None'

  return (
    <div className="space-y-8">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-black text-slate-900">Support Intelligence & Threat Dashboard</h1>
        <p className="mt-1 text-sm text-slate-500">
          Real-time customer complaint metrics and threat intelligence.
        </p>
      </div>

      {error && <div className="rounded-xl bg-rose-50 p-4 text-sm font-semibold text-rose-600">{error}</div>}

      {/* KPI STAT CARDS */}
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4 xl:grid-cols-4">
        <div className="card p-5 border-l-4 border-l-indigo-600 shadow-sm">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold uppercase text-slate-400">Total Conversations</span>
            <Database className="text-indigo-600" size={20} />
          </div>
          <p className="mt-3 text-2xl font-black text-slate-900">{total}</p>
          <span className="text-[11px] font-semibold text-slate-400">Processed threads & emails</span>
        </div>

        <div className="card p-5 border-l-4 border-l-rose-600 shadow-sm">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold uppercase text-slate-400">Security Threats</span>
            <ShieldAlert className="text-rose-600" size={20} />
          </div>
          <p className="mt-3 text-2xl font-black text-rose-600">{coverage.phishing || 0}</p>
          <span className="text-[11px] font-semibold text-rose-500">Phishing & domain flags</span>
        </div>

        <div className="card p-5 border-l-4 border-l-amber-500 shadow-sm">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold uppercase text-slate-400">Unresolved Complaints</span>
            <Flame className="text-amber-500" size={20} />
          </div>
          <p className="mt-3 text-2xl font-black text-amber-600">{s.unresolved_count || 0}</p>
          <span className="text-[11px] font-semibold text-slate-400">Needs agent follow-up</span>
        </div>

        <div className="card p-5 border-l-4 border-l-emerald-600 shadow-sm">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold uppercase text-slate-400">Resolved Threads</span>
            <CheckCircle2 className="text-emerald-600" size={20} />
          </div>
          <p className="mt-3 text-2xl font-black text-emerald-600">{s.resolved_count || 0}</p>
          <span className="text-[11px] font-semibold text-slate-400">Successfully closed</span>
        </div>
      </div>

      {/* SECONDARY KPI BANNER */}
      <div className="grid gap-4 sm:grid-cols-3">
        <div className="card p-4 bg-slate-900 text-white flex items-center gap-3">
          <Layers className="text-indigo-400 shrink-0" size={24} />
          <div>
            <div className="text-[10px] font-bold uppercase tracking-wider text-slate-400">Top Category</div>
            <div className="text-sm font-bold truncate text-indigo-200">{mostCommonCategory}</div>
          </div>
        </div>

        <div className="card p-4 bg-slate-900 text-white flex items-center gap-3">
          <FileSearch className="text-violet-400 shrink-0" size={24} />
          <div>
            <div className="text-[10px] font-bold uppercase tracking-wider text-slate-400">Frequent Issue</div>
            <div className="text-sm font-bold truncate text-violet-200">{mostFrequentIssue}</div>
          </div>
        </div>

        <div className="card p-4 bg-slate-900 text-white flex items-center gap-3">
          <AlertTriangle className="text-rose-400 shrink-0" size={24} />
          <div>
            <div className="text-[10px] font-bold uppercase tracking-wider text-slate-400">Critical Priority</div>
            <div className="text-sm font-bold text-rose-300">{s.critical_count || 0} critical issues</div>
          </div>
        </div>
      </div>

      {/* CHARTS GRID ROW 1 */}
      <div className="grid gap-6 lg:grid-cols-2">
        {/* SENTIMENT DISTRIBUTION DONUT CHART */}
        <div className="card p-5">
          <div className="flex items-center justify-between border-b pb-3">
            <h2 className="font-bold text-slate-900 flex items-center gap-2">
              <MessageSquare size={18} className="text-indigo-600" />
              Sentiment Distribution
            </h2>
            <span className="text-xs font-semibold text-slate-400">3 Sentiment Classes</span>
          </div>

          <div className="mt-4 h-64">
            {total === 0 || pieData.length === 0 ? (
              <div className="flex h-full items-center justify-center text-sm text-slate-400">
                No sentiment data available.
              </div>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={pieData}
                    cx="50%"
                    cy="50%"
                    innerRadius={55}
                    outerRadius={85}
                    paddingAngle={4}
                    dataKey="value"
                  >
                    {pieData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip formatter={(val) => [`${val} conversations`, 'Count']} />
                  <Legend verticalAlign="bottom" height={36} />
                </PieChart>
              </ResponsiveContainer>
            )}
          </div>
        </div>

        {/* RISK LEVEL BREAKDOWN */}
        <div className="card p-5">
          <div className="flex items-center justify-between border-b pb-3">
            <h2 className="font-bold text-slate-900 flex items-center gap-2">
              <ShieldCheck size={18} className="text-rose-600" />
              Risk Level Classification
            </h2>
            <span className="text-xs font-semibold text-slate-400">4 Risk Tiers</span>
          </div>

          <div className="mt-4 h-64">
            {total === 0 ? (
              <div className="flex h-full items-center justify-center text-sm text-slate-400">
                No risk classification data available.
              </div>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={riskData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                  <XAxis dataKey="name" stroke="#94a3b8" fontSize={12} />
                  <YAxis stroke="#94a3b8" fontSize={12} allowDecimals={false} />
                  <Tooltip formatter={(val) => [`${val} items`, 'Count']} />
                  <Bar dataKey="count" radius={[6, 6, 0, 0]}>
                    {riskData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.fill} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            )}
          </div>
        </div>
      </div>

      {/* CHARTS GRID ROW 2 */}
      <div className="grid gap-6 lg:grid-cols-2">
        {/* COMPLAINT CATEGORY DISTRIBUTION (HORIZONTAL BAR) */}
        <div className="card p-5">
          <div className="flex items-center justify-between border-b pb-3">
            <h2 className="font-bold text-slate-900">Complaint Category Distribution</h2>
            <span className="text-xs font-semibold text-slate-400">11 Categories</span>
          </div>

          <div className="mt-4 h-80">
            {total === 0 ? (
              <div className="flex h-full items-center justify-center text-sm text-slate-400">
                No category data available.
              </div>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart layout="vertical" data={categoryData} margin={{ top: 0, right: 20, left: 40, bottom: 0 }}>
                  <XAxis type="number" stroke="#94a3b8" fontSize={11} allowDecimals={false} />
                  <YAxis type="category" dataKey="name" stroke="#64748b" fontSize={11} width={130} />
                  <Tooltip formatter={(val, name, item) => [`${val} reports`, item.payload.fullCategory]} />
                  <Bar dataKey="count" fill="#6366F1" radius={[0, 4, 4, 0]} />
                </BarChart>
              </ResponsiveContainer>
            )}
          </div>
        </div>

        {/* FREQUENTLY REPORTED ISSUES (RANKED LIST) */}
        <div className="card p-5">
          <div className="flex items-center justify-between border-b pb-3">
            <h2 className="font-bold text-slate-900 flex items-center gap-2">
              <Activity size={18} className="text-violet-600" />
              Frequently Reported Issues
            </h2>
            <span className="text-xs font-semibold text-slate-400">NLP Cluster Signals</span>
          </div>

          <div className="mt-4 h-80">
            {issueData.length === 0 ? (
              <div className="flex h-full items-center justify-center text-sm text-slate-400">
                No recurring issues extracted yet.
              </div>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart layout="vertical" data={issueData} margin={{ top: 0, right: 20, left: 40, bottom: 0 }}>
                  <XAxis type="number" stroke="#94a3b8" fontSize={11} allowDecimals={false} />
                  <YAxis type="category" dataKey="issue" stroke="#64748b" fontSize={11} width={130} />
                  <Tooltip formatter={(val, name, item) => [`${val} occurrences`, item.payload.fullIssue]} />
                  <Bar dataKey="count" fill="#8B5CF6" radius={[0, 4, 4, 0]} />
                </BarChart>
              </ResponsiveContainer>
            )}
          </div>
        </div>
      </div>

      {/* COMPLAINT TREND TIMELINE */}
      <div className="card p-5">
        <div className="flex items-center justify-between border-b pb-3">
          <h2 className="font-bold text-slate-900">Complaint Volume Trends</h2>
          <span className="text-xs font-semibold text-slate-400">Weekly Activity Timeline</span>
        </div>

        <div className="mt-4 h-56">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={trendData} margin={{ top: 10, right: 20, left: -20, bottom: 0 }}>
              <XAxis dataKey="date" stroke="#94a3b8" fontSize={12} />
              <YAxis stroke="#94a3b8" fontSize={12} allowDecimals={false} />
              <Tooltip formatter={(val) => [`${val} complaints`, 'Volume']} />
              <Area type="monotone" dataKey="complaints" stroke="#6366F1" fill="#EEF2FF" strokeWidth={2} />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </div>
    </div>
  )
}
