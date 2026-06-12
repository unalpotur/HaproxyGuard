import { useState } from 'react'
import {
  scanSsl, analyzeCert,
  type SslReport, type CertificateInfo, type CipherAssessment,
} from './api'

const EXPIRY_COLOR: Record<string, string> = {
  expired: '#dc2626', critical: '#ea580c', warning: '#ca8a04', ok: '#16a34a',
}
const GRADE_COLOR: Record<string, string> = {
  A: '#16a34a', B: '#ca8a04', C: '#ea580c', F: '#dc2626',
}

function CertCard({ c }: { c: CertificateInfo }) {
  return (
    <div className="cert-card" style={{ borderLeftColor: EXPIRY_COLOR[c.expiry_status] }}>
      <div className="cert-head">
        <strong>{c.subject_cn || '(no CN)'}</strong>
        <span className="badge" style={{ background: EXPIRY_COLOR[c.expiry_status] }}>
          {c.expiry_status} · {c.days_remaining}d
        </span>
      </div>
      <small>issuer: {c.issuer_cn || '—'} · {c.key_type}{c.key_bits ? ` ${c.key_bits}` : ''} · {c.signature_algorithm}</small>
      {c.sans.length > 0 && <small>SAN: {c.sans.join(', ')}</small>}
      <small>valid until {new Date(c.not_after).toUTCString()}</small>
      {c.issues.map((i, k) => <p key={k} className="cert-issue">⚠ {i}</p>)}
    </div>
  )
}

function CipherRow({ a }: { a: CipherAssessment }) {
  return (
    <div className="cipher-row">
      <span className="grade" style={{ background: GRADE_COLOR[a.grade] }}>{a.grade}</span>
      <div>
        <strong>{a.section} · {a.bind}</strong>
        <small>min: {a.min_version ?? '—'} · ciphers: {a.ciphers ?? 'default'}</small>
        {a.issues.map((i, k) => <p key={k} className="cert-issue">⚠ {i}</p>)}
      </div>
    </div>
  )
}

export default function SslPanel({ config }: { config: string }) {
  const [report, setReport] = useState<SslReport | null>(null)
  const [pem, setPem] = useState('')
  const [pemCerts, setPemCerts] = useState<CertificateInfo[] | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  const run = async (fn: () => Promise<void>) => {
    setBusy(true); setError(null)
    try { await fn() } catch (e) { setError(e instanceof Error ? e.message : String(e)) }
    finally { setBusy(false) }
  }

  const scan = () => run(async () => setReport(await scanSsl(config, true)))
  const checkPem = () => run(async () => setPemCerts(await analyzeCert(pem)))

  return (
    <div className="ssl-panel">
      <div className="ssl-actions">
        <button onClick={scan} disabled={busy}>Scan config certificates</button>
      </div>
      {error && <p className="error">{error}</p>}

      {report && (
        <>
          <div className="summary">
            {Object.entries(report.summary).filter(([, n]) => n > 0).map(([k, n]) => (
              <span key={k} className="badge"
                    style={{ background: EXPIRY_COLOR[k] ?? '#475569' }}>{k}: {n}</span>
            ))}
          </div>
          {report.alerts.length > 0 && (
            <ul className="ssl-alerts">{report.alerts.map((a, i) => <li key={i}>{a}</li>)}</ul>
          )}

          <h4>Cipher / TLS grades</h4>
          {report.ciphers.length === 0 && <p className="empty">No SSL binds.</p>}
          {report.ciphers.map((a, i) => <CipherRow key={i} a={a} />)}

          <h4>Certificates</h4>
          {report.certificates.length === 0 && <p className="empty">No certificate references.</p>}
          {report.certificates.map((e, i) => (
            <div key={i} className="cert-entry">
              <code>{e.reference.path}</code> <em>({e.reference.kind} · {e.reference.section})</em>
              {!e.readable && e.error && <p className="cert-issue">⚠ {e.error}</p>}
              {e.certificates.map((c, k) => <CertCard key={k} c={c} />)}
            </div>
          ))}
        </>
      )}

      <h4>Inspect a PEM</h4>
      <textarea className="pem-input" value={pem} spellCheck={false}
                onChange={(e) => setPem(e.target.value)}
                placeholder="Paste a certificate (PEM) to inspect expiry & key…" />
      <button onClick={checkPem} disabled={busy || !pem.trim()}>Inspect certificate</button>
      {pemCerts && pemCerts.map((c, i) => <CertCard key={i} c={c} />)}
    </div>
  )
}
