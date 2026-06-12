import { useCallback, useEffect, useState } from 'react'
import { whoami, auditLog, type Principal, type AuditEntry } from './api'

const STATUS_COLOR: Record<string, string> = {
  ok: '#16a34a', denied: '#dc2626', error: '#ea580c',
}

export default function AuditPanel() {
  const [me, setMe] = useState<Principal | null>(null)
  const [entries, setEntries] = useState<AuditEntry[]>([])
  const [error, setError] = useState<string | null>(null)

  const refresh = useCallback(async () => {
    try {
      const [p, a] = await Promise.all([whoami(), auditLog()])
      setMe(p); setEntries(a); setError(null)
    } catch (e) { setError(e instanceof Error ? e.message : String(e)) }
  }, [])

  useEffect(() => {
    void refresh()
    const t = setInterval(() => void refresh(), 5000)
    return () => clearInterval(t)
  }, [refresh])

  return (
    <div className="audit-panel">
      {error && <p className="error">{error}</p>}
      {me && (
        <p className="whoami">
          Acting as <strong>{me.name}</strong>
          <span className={`role ${me.role}`}>{me.role}</span>
          {me.name === 'anonymous' && <small> — RBAC is open (set HG_ADMIN_KEY to enforce roles)</small>}
        </p>
      )}
      <table className="node-table">
        <thead>
          <tr><th>#</th><th>When</th><th>Actor</th><th>Action</th><th>Target</th><th>Status</th></tr>
        </thead>
        <tbody>
          {entries.length === 0 && <tr><td colSpan={6} className="empty">No audit entries yet.</td></tr>}
          {entries.map((e) => (
            <tr key={e.id}>
              <td>{e.id}</td>
              <td><small>{new Date(e.created_at).toLocaleTimeString()}</small></td>
              <td>{e.actor} <span className="role-mini">{e.role}</span></td>
              <td><code>{e.action}</code></td>
              <td><small>{e.target ?? '—'}</small></td>
              <td><span className="badge" style={{ background: STATUS_COLOR[e.status] ?? '#475569' }}>
                {e.status}{e.detail ? ` (${e.detail})` : ''}</span></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
