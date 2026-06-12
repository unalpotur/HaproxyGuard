import { useCallback, useEffect, useState } from 'react'
import {
  alertsEvaluate, alertsDispatch, alertChannels, addAlertChannel, removeAlertChannel,
  type Alert, type AlertChannel, type DispatchResult,
} from './api'

const SEV_COLOR: Record<string, string> = {
  critical: '#dc2626', high: '#ea580c', medium: '#ca8a04', low: '#2563eb', info: '#64748b',
}

function AlertRow({ a }: { a: Alert }) {
  return (
    <div className="alert-row" style={{ borderLeftColor: SEV_COLOR[a.severity] }}>
      <span className="badge" style={{ background: SEV_COLOR[a.severity] }}>{a.severity}</span>
      <span className="src">{a.source}</span>
      <strong>{a.title}</strong>
      <small>{a.detail}</small>
    </div>
  )
}

export default function AlertsPanel({ config, logs }: { config: string; logs?: string }) {
  const [alerts, setAlerts] = useState<Alert[] | null>(null)
  const [channels, setChannels] = useState<AlertChannel[]>([])
  const [dispatch, setDispatch] = useState<DispatchResult | null>(null)
  const [name, setName] = useState('')
  const [url, setUrl] = useState('')
  const [type, setType] = useState('webhook')
  const [minSev, setMinSev] = useState('high')
  const [error, setError] = useState<string | null>(null)

  const refresh = useCallback(async () => {
    try { setChannels(await alertChannels()); setError(null) }
    catch (e) { setError(e instanceof Error ? e.message : String(e)) }
  }, [])

  useEffect(() => { void refresh() }, [refresh])

  const guard = async (fn: () => Promise<void>) => {
    try { await fn() } catch (e) { setError(e instanceof Error ? e.message : String(e)) }
  }

  const evaluate = () => guard(async () => { setDispatch(null); setAlerts(await alertsEvaluate(config, logs ?? '')) })
  const send = () => guard(async () => {
    const r = await alertsDispatch(config, logs ?? ''); setDispatch(r); setAlerts(r.alerts)
  })
  const add = () => guard(async () => {
    if (!name.trim() || !url.trim()) throw new Error('name and URL required')
    await addAlertChannel(name, type, url, minSev); setName(''); setUrl(''); await refresh()
  })
  const remove = (id: string) => guard(async () => { await removeAlertChannel(id); await refresh() })

  return (
    <div className="alerts-panel">
      {error && <p className="error">{error}</p>}
      <p className="assistant-intro">
        Evaluates the current config (findings, TLS, drift) and optional logs into
        alerts, and notifies your webhook/Slack channels.
      </p>

      <div className="cluster-actions">
        <button onClick={evaluate}>Evaluate</button>
        <button onClick={send} disabled={channels.length === 0}>
          Evaluate &amp; notify ({channels.length})
        </button>
      </div>

      <h4>Channels</h4>
      <div className="enroll-row">
        <input placeholder="name" value={name} onChange={(e) => setName(e.target.value)} />
        <select value={type} onChange={(e) => setType(e.target.value)}>
          <option value="webhook">webhook</option>
          <option value="slack">slack</option>
        </select>
        <input placeholder="https://hooks…/url" value={url}
               onChange={(e) => setUrl(e.target.value)} style={{ flex: 1 }} />
        <select value={minSev} onChange={(e) => setMinSev(e.target.value)}>
          <option value="critical">critical+</option>
          <option value="high">high+</option>
          <option value="medium">medium+</option>
          <option value="low">low+</option>
        </select>
        <button onClick={add}>Add</button>
      </div>
      {channels.length === 0
        ? <p className="empty">No channels configured.</p>
        : channels.map((c) => (
          <div key={c.id} className="chan-row">
            <strong>{c.name}</strong>
            <span className="src">{c.type}</span>
            <code>{c.url}</code>
            <span className="src">≥ {c.min_severity}</span>
            <button className="warn" onClick={() => remove(c.id)}>✕</button>
          </div>
        ))}

      {dispatch && (
        <ul className="dispatch-results">
          {dispatch.results.map((r) => (
            <li key={r.channel_id} className={r.ok ? 'ok' : 'fail'}>
              {r.ok ? '✓' : '✗'} {r.name}: sent {r.sent} — {r.message}
            </li>
          ))}
        </ul>
      )}

      {alerts && (
        <>
          <h4>Alerts ({alerts.length})</h4>
          {alerts.length === 0
            ? <p className="empty">No alerts — deployment looks healthy 🎉</p>
            : alerts.map((a, i) => <AlertRow key={i} a={a} />)}
        </>
      )}
    </div>
  )
}
