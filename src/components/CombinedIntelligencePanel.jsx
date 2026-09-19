import { AlertTriangle, CheckCircle2, ShieldAlert, ShieldCheck, Sparkles, Lock, Key, Mail, Link as LinkIcon, FileText, Clock3, RefreshCw } from 'lucide-react'
import Badge from './Badge'

export default function CombinedIntelligencePanel({ analysis, text, conversationId, aiStatus, onToggleStatus, isUpdatingStatus }) {
  if (aiStatus === 'Rate Limited') {
    return (
      <div className="flex items-center gap-2.5 rounded-2xl bg-rose-50/80 p-4 text-xs font-semibold text-rose-900 border border-rose-200 shadow-xs">
        <AlertTriangle size={16} className="text-rose-600 shrink-0" />
        <div>
          <div className="font-bold text-rose-950 flex items-center gap-1.5">
            <span>Rate Limited</span>
            <span className="rounded-full bg-rose-200/80 px-2 py-0.5 text-[10px] uppercase tracking-wider font-extrabold text-rose-900">Groq Limit Exceeded</span>
          </div>
          <p className="text-[11px] text-rose-700 font-normal mt-0.5">
            Groq API free tier rate limit was reached during batch processing. Categorization stopped gracefully and remaining items set to Uncategorized.
          </p>
        </div>
      </div>
    )
  }

  if (aiStatus === 'Pending' || (!analysis && aiStatus !== 'Failed' && aiStatus !== 'Completed')) {
    return (
      <div className="flex items-center gap-2.5 rounded-2xl bg-amber-50/80 p-4 text-xs font-semibold text-amber-900 border border-amber-200 shadow-xs">
        <Sparkles size={16} className="animate-spin text-amber-600 shrink-0" />
        <div>
          <div className="font-bold text-amber-950 flex items-center gap-1.5">
            <span>Analyzing...</span>
            <span className="rounded-full bg-amber-200/80 px-2 py-0.5 text-[10px] uppercase tracking-wider font-extrabold text-amber-900">Background Task</span>
          </div>
          <p className="text-[11px] text-amber-700 font-normal mt-0.5">
            Heavy AI threat intelligence & NLP categorization is running asynchronously. Updated insights will appear shortly.
          </p>
        </div>
      </div>
    )
  }

  const sec = analysis.security || {}
  const risk = (sec.risk_level || analysis.risk?.risk_level || 'low').toLowerCase()
  const category = analysis.category || analysis.classification?.category || 'Other'
  const sentiment = (analysis.sentiment?.label || analysis.sentiment || 'neutral').toLowerCase()
  const emotion = analysis.emotion || 'None'
  const priority = (analysis.priority || 'medium').toLowerCase()
  const resolutionStatus = analysis.resolution_status || 'Unresolved'
  const summary = analysis.summary || 'No summary available.'
  const action = analysis.recommended_action || 'Review inquiry and process response.'

  const threatType = sec.threat_type || (sec.suspicious_url || sec.suspicious_email ? 'phishing' : 'none')
  const suspiciousUrl = sec.suspicious_url ?? (sec.url_details?.some(u => u.is_suspicious) || false)
  const suspiciousEmail = sec.suspicious_email ?? (sec.email_details?.some(e => e.domain_mismatch || e.potential_impersonation) || false)
  const suspiciousDomain = sec.suspicious_domain ?? (suspiciousUrl || suspiciousEmail)
  
  const socialTechs = sec.social_engineering_techniques || []
  const socialEngineering = sec.social_engineering || (socialTechs.length > 0 ? 'Detected' : 'None')
  
  const credentialRequest = sec.credential_request ?? (socialTechs.some(t => /credential|password/i.test(t)) || /password|login credentials/i.test(text || ''))
  const otpRequest = sec.otp_request ?? (socialTechs.some(t => /otp|2fa/i.test(t)) || /otp|2fa|verification code/i.test(text || ''))

  const riskBadgeStyles = {
    critical: 'bg-rose-600 text-white shadow-rose-200',
    high: 'bg-orange-500 text-white shadow-orange-200',
    medium: 'bg-amber-500 text-white shadow-amber-200',
    low: 'bg-emerald-600 text-white shadow-emerald-200',
  }

  const sentimentStyles = {
    positive: 'bg-emerald-50 text-emerald-700 border-emerald-200',
    negative: 'bg-rose-50 text-rose-700 border-rose-200',
    neutral: 'bg-slate-100 text-slate-700 border-slate-200',
  }

  return (
    <div className="space-y-4">
      {conversationId && (
        <div className="flex items-center justify-between border-b pb-3">
          <span className="text-xs font-bold uppercase tracking-wider text-slate-400">Canonical Output</span>
          <span className="rounded-lg bg-slate-100 px-2.5 py-1 text-xs font-mono font-bold text-slate-600">
            ID: {conversationId}
          </span>
        </div>
      )}

      <div className="grid gap-4 md:grid-cols-2">
        {/* CUSTOMER INTELLIGENCE PANEL */}
        <div className="rounded-2xl border border-blue-100 bg-blue-50/40 p-5 shadow-sm">
          <div className="flex items-center justify-between border-b border-blue-100 pb-3">
            <h3 className="flex items-center gap-2 text-sm font-bold text-blue-900">
              <FileText size={16} className="text-blue-600" />
              CUSTOMER INTELLIGENCE
            </h3>
            <span className="rounded-full bg-blue-100 px-2.5 py-0.5 text-xs font-bold text-blue-800">
              Support Insights
            </span>
          </div>

          <div className="mt-4 space-y-3.5 text-xs">
            <div className="flex items-center justify-between">
              <span className="font-medium text-slate-500">Category:</span>
              <span className="rounded-lg bg-white px-2.5 py-1 font-semibold text-slate-800 shadow-sm border border-slate-200">
                {category}
              </span>
            </div>

            <div className="flex items-center justify-between">
              <span className="font-medium text-slate-500">Sentiment & Emotion:</span>
              <div className="flex items-center gap-1.5">
                <span className={`rounded-md border px-2 py-0.5 font-bold capitalize ${sentimentStyles[sentiment] || sentimentStyles.neutral}`}>
                  {sentiment}
                </span>
                {emotion && emotion !== 'None' && (
                  <span className="rounded-md bg-purple-50 px-2 py-0.5 font-semibold text-purple-700 border border-purple-200">
                    {emotion}
                  </span>
                )}
              </div>
            </div>

            <div className="flex items-center justify-between">
              <span className="font-medium text-slate-500">Priority Level:</span>
              <Badge value={priority} />
            </div>

            <div className="flex items-center justify-between">
              <span className="font-medium text-slate-500">Resolution Status:</span>
              {onToggleStatus ? (
                <button
                  onClick={() => onToggleStatus(resolutionStatus.toLowerCase() === 'resolved' ? 'Unresolved' : 'Resolved')}
                  disabled={isUpdatingStatus}
                  className={`flex items-center gap-1.5 rounded-full px-3 py-1 font-bold text-xs transition cursor-pointer hover:scale-105 active:scale-95 border ${
                    resolutionStatus.toLowerCase() === 'resolved'
                      ? 'bg-emerald-100 text-emerald-800 border-emerald-300 hover:bg-emerald-200'
                      : 'bg-amber-100 text-amber-900 border-amber-300 hover:bg-amber-200'
                  }`}
                  title="Click to toggle Resolution Status"
                >
                  {isUpdatingStatus ? (
                    <RefreshCw size={13} className="animate-spin text-slate-600" />
                  ) : resolutionStatus.toLowerCase() === 'resolved' ? (
                    <CheckCircle2 size={13} className="text-emerald-700" />
                  ) : (
                    <Clock3 size={13} className="text-amber-700" />
                  )}
                  <span>{resolutionStatus}</span>
                  <span className="text-[10px] text-slate-400 font-normal ml-0.5">(Click to change)</span>
                </button>
              ) : (
                <span className={`rounded-full px-2.5 py-0.5 font-bold text-xs ${resolutionStatus.toLowerCase() === 'resolved' ? 'bg-emerald-100 text-emerald-800' : 'bg-amber-100 text-amber-800'}`}>
                  {resolutionStatus}
                </span>
              )}
            </div>

            <div className="pt-1">
              <span className="font-medium text-slate-500">Executive Summary:</span>
              <p className="mt-1 rounded-xl bg-white p-3 font-normal leading-relaxed text-slate-700 border border-blue-100 shadow-sm">
                {summary}
              </p>
            </div>
          </div>
        </div>

        {/* SECURITY INTELLIGENCE PANEL */}
        <div className={`rounded-2xl border p-5 shadow-sm ${risk === 'low' ? 'border-slate-200 bg-slate-50/50' : 'border-rose-200 bg-rose-50/30'}`}>
          <div className="flex items-center justify-between border-b border-rose-100 pb-3">
            <h3 className="flex items-center gap-2 text-sm font-bold text-slate-900">
              {risk === 'low' ? <ShieldCheck size={16} className="text-emerald-600" /> : <ShieldAlert size={16} className="text-rose-600" />}
              SECURITY INTELLIGENCE
            </h3>
            <span className={`rounded-full px-3 py-1 text-xs font-black shadow-sm capitalize ${riskBadgeStyles[risk] || riskBadgeStyles.low}`}>
              Risk: {risk}
            </span>
          </div>

          <div className="mt-4 space-y-3.5 text-xs">
            <div className="flex items-center justify-between">
              <span className="font-medium text-slate-500">Threat Type:</span>
              <span className={`font-bold capitalize ${threatType === 'phishing' ? 'text-rose-600' : threatType === 'social_engineering' ? 'text-orange-600' : 'text-slate-700'}`}>
                {threatType}
              </span>
            </div>

            <div className="flex items-center justify-between">
              <span className="font-medium text-slate-500">Suspicious URL / Domain:</span>
              <div className="flex gap-1.5">
                <span className={`rounded px-2 py-0.5 font-bold ${suspiciousUrl ? 'bg-rose-100 text-rose-700' : 'bg-emerald-100 text-emerald-700'}`}>
                  URL: {suspiciousUrl ? 'Detected' : 'Not Detected'}
                </span>
                <span className={`rounded px-2 py-0.5 font-bold ${suspiciousDomain ? 'bg-rose-100 text-rose-700' : 'bg-slate-100 text-slate-600'}`}>
                  Domain: {suspiciousDomain ? 'Suspicious' : 'Clean'}
                </span>
              </div>
            </div>

            <div className="flex items-center justify-between">
              <span className="font-medium text-slate-500">Suspicious Email Address:</span>
              <span className={`rounded px-2 py-0.5 font-bold ${suspiciousEmail ? 'bg-rose-100 text-rose-700' : 'bg-emerald-100 text-emerald-700'}`}>
                {suspiciousEmail ? 'Impersonation Flagged' : 'Normal Domain'}
              </span>
            </div>

            <div className="flex items-center justify-between">
              <span className="font-medium text-slate-500">Social Engineering:</span>
              <span className={`font-bold ${socialEngineering === 'Detected' ? 'text-rose-600' : 'text-slate-600'}`}>
                {socialEngineering}
              </span>
            </div>

            <div className="flex items-center justify-between">
              <span className="font-medium text-slate-500">Credential & OTP Flags:</span>
              <div className="flex gap-1.5">
                <span className={`flex items-center gap-1 rounded px-2 py-0.5 font-bold ${credentialRequest ? 'bg-rose-100 text-rose-700' : 'bg-slate-100 text-slate-500'}`}>
                  <Lock size={10} /> Credential: {credentialRequest ? 'Yes' : 'No'}
                </span>
                <span className={`flex items-center gap-1 rounded px-2 py-0.5 font-bold ${otpRequest ? 'bg-rose-100 text-rose-700' : 'bg-slate-100 text-slate-500'}`}>
                  <Key size={10} /> OTP: {otpRequest ? 'Yes' : 'No'}
                </span>
              </div>
            </div>

            {/* Social Engineering Techniques */}
            {socialTechs.length > 0 && (
              <div className="rounded-lg bg-rose-50 p-2.5 border border-rose-200">
                <span className="font-bold text-rose-800">Detected Techniques:</span>
                <div className="mt-1 flex flex-wrap gap-1">
                  {socialTechs.map((t, idx) => (
                    <span key={idx} className="rounded bg-rose-200/60 px-2 py-0.5 font-semibold text-rose-900">
                      {t}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {/* Detailed URL list if any suspicious URL */}
            {sec.url_details?.some(u => u.is_suspicious) && (
              <div className="rounded-lg bg-white p-2.5 border border-rose-200">
                <span className="font-bold text-rose-800 flex items-center gap-1">
                  <LinkIcon size={12} /> Flagged Link Analysis:
                </span>
                {sec.url_details.filter(u => u.is_suspicious).map((u, i) => (
                  <div key={i} className="mt-1 text-[11px] text-slate-700 truncate">
                    <span className="font-mono text-rose-600">{u.url}</span>
                    <div className="text-[10px] text-slate-500">{u.potential_issue} (Risk Score: {u.url_risk_score})</div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>

      {/* RECOMMENDED ACTION CALLOUT BOX */}
      <div className={`rounded-2xl border p-4 shadow-sm flex items-start gap-3 ${risk === 'critical' || risk === 'high' ? 'bg-rose-600 text-white border-rose-700' : risk === 'medium' ? 'bg-amber-500 text-white border-amber-600' : 'bg-indigo-600 text-white border-indigo-700'}`}>
        {risk === 'critical' || risk === 'high' ? (
          <AlertTriangle size={22} className="shrink-0 mt-0.5 text-rose-100" />
        ) : (
          <CheckCircle2 size={22} className="shrink-0 mt-0.5 text-indigo-100" />
        )}
        <div>
          <span className="text-xs font-black uppercase tracking-wider opacity-90">Recommended Action</span>
          <p className="mt-0.5 text-sm font-medium leading-snug">{action}</p>
        </div>
      </div>
    </div>
  )
}
