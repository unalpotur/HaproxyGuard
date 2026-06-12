import { useEffect, useState } from 'react'
import {
  fetchSecurityCatalog, generateSecurity, securityPosture,
  type SecurityCatalog, type GeneratedConfig, type SecurityPosture,
} from './api'

const CATEGORY_COLOR: Record<string, string> = {
  'rate-limit': '#2563eb', ddos: '#dc2626', geo: '#7c3aed', admin: '#0891b2',
}

function scoreColor(score: number): string {
  if (score >= 80) return '#16a34a'
  if (score >= 50) return '#ca8a04'
  return '#dc2626'
}

export default function SecurityPanel({ config }: { config: string }) {
  const [cat, setCat] = useState<SecurityCatalog | null>(null)
  const [preset, setPreset] = useState('basic')
  const [gen, setGen] = useState<GeneratedConfig | null>(null)
  const [posture, setPosture] = useState<SecurityPosture | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [copied, setCopied] = useState(false)

  useEffect(() => {
    fetchSecurityCatalog().then(setCat).catch((e) => setError(String(e)))
  }, [])

  const run = async (fn: () => Promise<void>) => {
    setBusy(true); setError(null)
    try { await fn() } catch (e) { setError(e instanceof Error ? e.message : String(e)) }
    finally { setBusy(false) }
  }

  const generate = () => run(async () => { setGen(await generateSecurity(preset)); setCopied(false) })
  const scan = () => run(async () => setPosture(await securityPosture(config)))
  const copy = () => {
    if (gen) { void navigator.clipboard.writeText(gen.snippet); setCopied(true) }
  }

  return (
    <div className="sec-panel">
      {error && <p className="error">{error}</p>}

      <h4>Security posture</h4>
      <div className="sec-actions">
        <button onClick={scan} disabled={busy}>Assess current config</button>
        {posture && (
          <span className="score" style={{ background: scoreColor(posture.score) }}>
            {posture.score}/100 · {posture.present_count}/{posture.total} controls
          </span>
        )}
      </div>
      {posture && (
        <div className="sec-controls">
          {posture.controls.map((c) => (
            <div key={c.id} className={`sec-control ${c.present ? 'on' : 'off'}`}>
              <span className="cat" style={{ background: CATEGORY_COLOR[c.category] ?? '#475569' }}>
                {c.category}
              </span>
              <span className="mark">{c.present ? '✓' : '✗'}</span>
              <div>
                <strong>{c.name}</strong>
                <small>{c.detail}</small>
              </div>
            </div>
          ))}
        </div>
      )}

      <h4>Generate hardening preset</h4>
      <div className="sec-actions">
        <select value={preset} onChange={(e) => setPreset(e.target.value)}>
          {cat?.presets.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
        </select>
        <button onClick={generate} disabled={busy}>Generate snippet</button>
        {gen && <button onClick={copy}>{copied ? 'Copied ✓' : 'Copy'}</button>}
      </div>
      {cat && (
        <p className="preset-desc">
          {cat.presets.find((p) => p.id === preset)?.description}
        </p>
      )}
      {gen && <pre className="snippet">{gen.snippet}</pre>}
    </div>
  )
}
