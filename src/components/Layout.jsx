import { NavLink, Outlet, useNavigate } from 'react-router-dom'
import { BarChart3, Inbox, Link2, LogOut, MessageSquare, ShieldCheck, X, Mail, MessageCircle, Instagram } from 'lucide-react'
import { useAuth } from '../context/AuthContext'
import { useEffect, useState } from 'react'
import api from '../api'

const links = [
  { to: '/', label: 'Dashboard', icon: BarChart3 },
  { to: '/conversations', label: 'Conversations', icon: MessageSquare },
  { to: '/connections', label: 'Connections', icon: Link2 }
]

const inboxes = [
  { to: '/connections/gmail', label: 'Mails Inbox', icon: Mail, showThreatBadge: true },
  { to: '/connections/whatsapp', label: 'WhatsApp', icon: MessageCircle },
  { to: '/connections/instagram', label: 'Instagram', icon: Instagram }
]

export default function Layout() {
  const { user, logout } = useAuth()
  const navigate = useNavigate()
  const [open, setOpen] = useState(false)
  const [threatCount, setThreatCount] = useState(0)

  useEffect(() => {
    api.get('/dashboard-stats')
      .then(r => setThreatCount(r.data?.coverage?.phishing || 0))
      .catch(() => setThreatCount(0))
  }, [])

  const signOut = () => {
    logout()
    navigate('/login')
  }

  return (
    <div className="flex min-h-screen bg-slate-50">
      <aside className={`${open ? 'translate-x-0' : '-translate-x-full'} fixed inset-y-0 left-0 z-30 w-64 border-r border-slate-200 bg-white p-5 transition md:static md:translate-x-0`}>
        <div className="mb-10 flex items-center justify-between">
          <div className="flex items-center gap-2 text-xl font-black text-indigo-700">
            <ShieldCheck /> SentiDesk
          </div>
          <button className="md:hidden" onClick={() => setOpen(false)}>
            <X />
          </button>
        </div>

        <nav className="space-y-1">
          {links.map(({ to, label, icon: Icon }) => (
            <NavLink
              key={to}
              to={to}
              end={to === '/'}
              onClick={() => setOpen(false)}
              className={({ isActive }) =>
                `flex items-center gap-3 rounded-xl px-3 py-3 text-sm font-semibold ${
                  isActive ? 'bg-indigo-50 text-indigo-700 font-extrabold' : 'text-slate-500 hover:bg-slate-50'
                }`
              }
            >
              <Icon size={18} />
              {label}
            </NavLink>
          ))}

          <p className="px-3 pb-1 pt-6 text-[10px] font-bold uppercase tracking-widest text-slate-400">
            Provider inboxes
          </p>

          {inboxes.map(({ to, label, icon: Icon, showThreatBadge }) => (
            <NavLink
              key={to}
              to={to}
              onClick={() => setOpen(false)}
              className={({ isActive }) =>
                `flex items-center justify-between rounded-xl px-3 py-2.5 text-sm font-semibold ${
                  isActive ? 'bg-indigo-50 text-indigo-700 font-extrabold' : 'text-slate-500 hover:bg-slate-50'
                }`
              }
            >
              <div className="flex items-center gap-3">
                <Icon size={17} />
                {label}
              </div>
              {showThreatBadge && threatCount > 0 && (
                <span className="rounded-full bg-rose-500 px-2 py-0.5 text-[10px] font-black text-white shadow-xs">
                  {threatCount}
                </span>
              )}
            </NavLink>
          ))}
        </nav>

        <div className="absolute bottom-5 left-5 right-5 border-t pt-4">
          <div className="mb-3 truncate text-xs text-slate-500 font-medium">{user?.email}</div>
          <button onClick={signOut} className="flex items-center gap-2 text-xs font-bold text-slate-500 hover:text-rose-600 cursor-pointer">
            <LogOut size={16} /> Sign out
          </button>
        </div>
      </aside>

      <main className="min-w-0 flex-1">
        <header className="flex items-center justify-between border-b bg-white px-5 py-4 md:px-8 shadow-xs">
          <button className="md:hidden" onClick={() => setOpen(true)}>
            <Inbox />
          </button>
          <div className="text-xs font-bold uppercase tracking-wider text-slate-400">
            Customer Intelligence & Threat Detection Workspace
          </div>
          <div className="h-9 w-9 rounded-full bg-indigo-100 text-center leading-9 font-black text-indigo-700 text-sm">
            {(user?.email || 'U')[0].toUpperCase()}
          </div>
        </header>
        <div className="p-5 md:p-8">
          <Outlet />
        </div>
      </main>
    </div>
  )
}
