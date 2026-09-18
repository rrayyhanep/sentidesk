import { createContext, useContext, useEffect, useState } from 'react'
import api from '../api'

const AuthContext = createContext(null)
export function AuthProvider({ children }) {
  const [user, setUser] = useState(null)
  const [loading, setLoading] = useState(true)
  useEffect(() => {
    if (!localStorage.getItem('sentidesk_token')) return setLoading(false)
    api.get('/auth/me').then(r => setUser(r.data)).catch(() => localStorage.removeItem('sentidesk_token')).finally(() => setLoading(false))
  }, [])
  const login = async credentials => { const { data } = await api.post('/auth/login', { email: credentials.email, password: credentials.password }); localStorage.setItem('sentidesk_token', data.access_token || data.token); const me = await api.get('/auth/me'); setUser(me.data) }
  const register = async credentials => {
    const { data } = await api.post('/auth/register', { email: credentials.email, password: credentials.password })
    if (data.verification_required) return data
    localStorage.setItem('sentidesk_token', data.access_token || data.token)
    const me = await api.get('/auth/me'); setUser(me.data)
    return data
  }
  const logout = () => { localStorage.removeItem('sentidesk_token'); setUser(null) }
  return <AuthContext.Provider value={{ user, loading, login, register, logout }}>{children}</AuthContext.Provider>
}
export const useAuth = () => useContext(AuthContext)
