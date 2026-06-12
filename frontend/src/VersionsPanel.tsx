import { useCallback, useEffect, useState } from 'react'
import {
  listVersions, saveVersion, versionDiff, restoreVersion,
  type ConfigVersion,
} from './api'

type Props = {
  config: string
  onRestore: (content: string) => void
}

export default function VersionsPanel({ config, onRestore }: Props) {
  const [versions, setVersions] = useState<ConfigVersion[]>([])
  const [label, setLabel] = useState('')
  const [message, setMessage] = useState('')
  const [pick, setPick] = useState<string[]>([])
  const [diff, setDiff] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)

  const refresh = useCallback(async () => {
    try { setVersions(await listVersions()); setError(null) }
    catch (e) { setError(e instanceof Error ? e.message : String(e)) }
  }, [])

  useEffect(() => { void refresh() }, [refresh])

  const guard = async (fn: () => Promise<void>) => {
    try { await fn() } catch (e) { setError(e instanceof Error ? e.message : String(e)) }
  }

  const save = () => guard(async () => {
    await saveVersion(config, label, message); setLabel(''); setMessage(''); await refresh()
  })

  const togglePick = (id: string) => setPick((p) => {
    if (p.includes(id)) return p.filter((x) => x !== id)
    return [...p, id].slice(-2)  // keep the two most recent picks
  })

  const showDiff = () => guard(async () => {
    if (pick.length !== 2) throw new Error('select exactly two versions to diff')
    const [a, b] = pick
    const r = await versionDiff(a, b)
    setDiff(r.diff || '(no differences)')
  })

  const restore = (id: string) => guard(async () => {
    const r = await restoreVersion(id)
    onRestore(r.content)
    await refresh()
  })

  return (
    <div className="versions-panel">
      {error && <p className="error">{error}</p>}
      <p className="assistant-intro">
        Git-style history of the editor config. Save snapshots, diff any two, and
        restore a previous version into the editor.
      </p>

      <div className="enroll-row">
        <input placeholder="label (e.g. before-tls-change)" value={label}
               onChange={(e) => setLabel(e.target.value)} />
        <input placeholder="message" value={message} style={{ flex: 1 }}
               onChange={(e) => setMessage(e.target.value)} />
        <button onClick={save}>Save current config</button>
      </div>

      <div className="cluster-actions">
        <button onClick={showDiff} disabled={pick.length !== 2}>
          Diff selected ({pick.length}/2)
        </button>
        {pick.length === 2 && <small>{pick[0]} → {pick[1]}</small>}
      </div>

      <table className="node-table">
        <thead>
          <tr><th></th><th>Version</th><th>Author</th><th>Message</th><th>Hash</th><th>When</th><th></th></tr>
        </thead>
        <tbody>
          {versions.length === 0 && <tr><td colSpan={7} className="empty">No versions saved yet.</td></tr>}
          {versions.map((v) => (
            <tr key={v.id}>
              <td><input type="checkbox" checked={pick.includes(v.id)} onChange={() => togglePick(v.id)} /></td>
              <td><strong>{v.id}</strong>{v.label && <span className="label">{v.label}</span>}</td>
              <td>{v.author}</td>
              <td><small>{v.message || '—'}</small></td>
              <td><code>{v.content_hash}</code></td>
              <td><small>{new Date(v.created_at).toLocaleString()}</small></td>
              <td><button onClick={() => restore(v.id)}>Restore</button></td>
            </tr>
          ))}
        </tbody>
      </table>

      {diff !== null && (
        <>
          <h4>Diff</h4>
          <pre className="diff">{diff}</pre>
        </>
      )}
    </div>
  )
}
