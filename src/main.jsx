import React from 'react'
import { createRoot } from 'react-dom/client'
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { AuthProvider } from './context/AuthContext'
import ProtectedRoute from './components/ProtectedRoute'
import Layout from './components/Layout'
import Login from './pages/Login'
import Dashboard from './pages/Dashboard'
import Conversations from './pages/Conversations'
import ConversationDetail from './pages/ConversationDetail'
import Connections from './pages/Connections'
import ProviderInbox from './pages/ProviderInbox'
import OAuthCallback from './pages/OAuthCallback'
import CategoryPage from './pages/CategoryPage'
import './index.css'

createRoot(document.getElementById('root')).render(
  <React.StrictMode><BrowserRouter><AuthProvider><Routes>
    <Route path="/login" element={<Login />} />
    <Route element={<ProtectedRoute />}><Route element={<Layout />}>
      <Route index element={<Dashboard />} />
      <Route path="conversations" element={<Conversations />} />
      <Route path="conversations/:id" element={<ConversationDetail />} />
      <Route path="connections" element={<Connections />} />
      <Route path="connections/:provider/oauth/callback" element={<OAuthCallback />} />
      <Route path="connections/:provider" element={<ProviderInbox />} />
      <Route path="category/:type" element={<CategoryPage />} />
    </Route></Route>
    <Route path="*" element={<Navigate to="/" replace />} />
  </Routes></AuthProvider></BrowserRouter></React.StrictMode>
)
