import { useEffect, useState } from 'react'
import { CheckCircle2, XCircle } from 'lucide-react'
import { useParams, useSearchParams } from 'react-router-dom'
import api from '../api'

export default function OAuthCallback() {
  const { provider } = useParams()
  const [params] = useSearchParams()
  const [result, setResult] = useState({ loading: true, error: '' })
  useEffect(() => {
    const finish = async () => {
      try {
        if (params.get('error')) throw new Error(params.get('error_description') || params.get('error'))
        const { data } = await api.get(`/connections/${provider}/oauth/callback`, { params: { code: params.get('code'), state: params.get('state') } })
        const message = data.message || 'Authorization response received. Refresh Connections to confirm setup.'
        if (window.opener) window.opener.postMessage({ sentideskOAuth: true, message }, window.location.origin)
        setResult({ loading: false, message })
        if (window.opener) setTimeout(() => window.close(), 1200)
      } catch (err) { setResult({ loading: false, error: err.response?.data?.detail || err.message || 'Authorization could not be completed.' }) }
    }
    finish()
  }, [provider, params])
  return <main className="flex min-h-screen items-center justify-center bg-slate-50 p-6"><div className="card max-w-md p-8 text-center">{result.loading ? <p className="text-slate-600">Finishing {provider} authorization…</p> : result.error ? <><XCircle className="mx-auto text-rose-600" size={38}/><h1 className="mt-4 text-xl font-bold">Authorization failed</h1><p className="mt-2 text-sm text-rose-700">{result.error}</p></> : <><CheckCircle2 className="mx-auto text-emerald-600" size={38}/><h1 className="mt-4 text-xl font-bold">Authorization response received</h1><p className="mt-2 text-sm text-slate-600">{result.message}</p></>}</div></main>
}
