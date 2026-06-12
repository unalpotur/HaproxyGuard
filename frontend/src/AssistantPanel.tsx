import { useEffect, useState } from 'react'
import {
  assistantStatus, assistantAnalyze,
  type AssistantReport, type RootCause,
} from './api'

const RISK_COLOR: Record<string, string> = {
  low: '#16a34a', medium: '#ca8a04', high: '#ea580c', critical: '#dc2626',
}
const SEV_COLOR: Record<string, string> = {
  critical: '#dc2626', high: '#ea580c', medium: '#ca8a04', low: '#2563eb', info: '#64748b',
}

function CauseRow({ c }: { c: RootCause }) {
  return (
    <div className="cause" style={{ borderLeftColor: SEV_COLOR[c.severity] ?? '#475569' }}>
      <div className="cause-head">
        <span className="badge" style={{ background: SEV_COLOR[c.severity] ?? '#475569' }}>
          {c.severity}
        </span>
        <strong>{c.title}</strong>
        <span className="category">{c.category}</span>
      </div>
      <p>{c.evidence}</p>
    </div>
  )
}

export default function AssistantPanel({ config }: { config: string }) {
  const [logs, setLogs] = useState('')
  const [useLlm, setUseLlm] = useState(false)
  const [llmAvailable, setLlmAvailable] = useState(false)
  const [report, setReport] = useState<AssistantReport | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    assistantStatus().then((s) => { setLlmAvailable(s.llm_available); setUseLlm(s.llm_available) })
      .catch(() => setLlmAvailable(false))
  }, [])

  const run = async () => {
    setBusy(true); setError(null)
    try { setReport(await assistantAnalyze(config, logs, useLlm && llmAvailable)) }
    catch (e) { setError(e instanceof Error ? e.message : String(e)) }
    finally { setBusy(false) }
  }

  return (
    <div className="assistant-panel">
      <p className="assistant-intro">
        Diagnoses the deployment from its config, security &amp; TLS posture, and
        (optionally) access logs — producing a risk score, root causes and fixes.
      </p>
      <textarea
        className="logs-input" value={logs} spellCheck={false}
        onChange={(e) => setLogs(e.target.value)}
        placeholder="Optional: paste HAProxy access logs (option httplog) for error-rate analysis…"
      />
      <div className="assistant-actions">
        <button onClick={run} disabled={busy}>{busy ? 'Analyzing…' : 'Diagnose'}</button>
        <label className={llmAvailable ? '' : 'disabled'} title={
          llmAvailable ? 'Use Claude for a written analysis'
            : 'Set ANTHROPIC_API_KEY on the server to enable'}>
          <input type="checkbox" checked={useLlm && llmAvailable} disabled={!llmAvailable}
                 onChange={(e) => setUseLlm(e.target.checked)} />
          AI narrative {llmAvailable ? '' : '(unavailable)'}
        </label>
      </div>
      {error && <p className="error">{error}</p>}

      {report && (
        <>
          <div className="risk" style={{ borderColor: RISK_COLOR[report.risk_level] }}>
            <span className="risk-score" style={{ background: RISK_COLOR[report.risk_level] }}>
              {report.risk_score}
            </span>
            <div>
              <strong style={{ color: RISK_COLOR[report.risk_level] }}>
                {report.risk_level.toUpperCase()} RISK
              </strong>
              <p>{report.summary}</p>
            </div>
          </div>

          {report.llm_narrative && (
            <div className="narrative">
              <h4>AI analysis {report.used_llm && <span className="badge ai">Claude</span>}</h4>
              <p>{report.llm_narrative}</p>
            </div>
          )}

          {report.log_summary && report.log_summary.parsed > 0 && (
            <p className="log-stats">
              Logs: {report.log_summary.parsed} parsed · error rate{' '}
              {(report.log_summary.error_rate * 100).toFixed(1)}% · {report.log_summary.slow_count} slow
              {report.log_summary.avg_response_ms != null &&
                ` · avg ${report.log_summary.avg_response_ms}ms`}
            </p>
          )}

          <h4>Root causes</h4>
          {report.root_causes.length === 0
            ? <p className="empty">No significant issues detected 🎉</p>
            : report.root_causes.map((c, i) => <CauseRow key={i} c={c} />)}

          <h4>Recommendations</h4>
          <ol className="recs">
            {report.recommendations.map((r, i) => (
              <li key={i}>
                <span className={`prio ${r.priority}`}>{r.priority}</span>
                <strong>{r.action}</strong>
                <small>{r.rationale}</small>
              </li>
            ))}
          </ol>
        </>
      )}
    </div>
  )
}
