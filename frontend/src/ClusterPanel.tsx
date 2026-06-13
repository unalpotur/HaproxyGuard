import { useCallback, useEffect, useState, type CSSProperties } from 'react'
import {
  clusterNodes, clusterOverview, clusterEnroll, clusterDeploy, clusterDeployCheck,
  clusterRollback, clusterRemove, agentHeartbeat, nodeAction,
  type ClusterNode, type ClusterOverview,
} from './api'

const shortPath = (p: string) => p.split('/').pop() || p

const STATUS_COLOR: Record<string, string> = {
  online: '#16a34a', offline: '#dc2626', pending: '#ca8a04',
}
const SVC_COLOR: Record<string, string> = {
  running: '#16a34a', stopped: '#ef4444', unknown: '#64748b',
}

function parseLabels(s: string): Record<string, string> {
  const out: Record<string, string> = {}
  for (const part of s.split(',').map((p) => p.trim()).filter(Boolean)) {
    const [k, v] = part.split('=')
    if (k && v) out[k.trim()] = v.trim()
  }
  return out
}

export default function ClusterPanel({ config, onConfigChange }: { config: string; onConfigChange?: (c: string) => void }) {
  const [nodes, setNodes] = useState<ClusterNode[]>([])
  const [overview, setOverview] = useState<ClusterOverview | null>(null)
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [tokens, setTokens] = useState<Record<string, string>>({})
  const [name, setName] = useState('')
  const [address, setAddress] = useState('')
  const [labels, setLabels] = useState('role=edge')
  const [sshHost, setSshHost] = useState('')
  const [sshUser, setSshUser] = useState('root')
  const [sshPass, setSshPass] = useState('')
  const [autoDeploy, setAutoDeploy] = useState(false)
  const [manageMode, setManageMode] = useState("auto")
  const [error, setError] = useState<string | null>(null)
  const [notice, setNotice] = useState<string | null>(null)
  // The node we are currently fetching config from, plus the timestamp of its
  // previous action result — so we only adopt a result newer than that.
  const [fetching, setFetching] = useState<{ id: string; since: number } | null>(null)
  // Auxiliary files (certs/maps/errorfiles) captured with the last fetched
  // config, shipped alongside it on the next deploy. path -> base64.
  const [bundleFiles, setBundleFiles] = useState<Record<string, string>>({})

  const refresh = useCallback(async () => {
    try {
      const [n, o] = await Promise.all([clusterNodes(), clusterOverview()])
      setNodes(n); setOverview(o); setError(null)
    } catch (e) { setError(e instanceof Error ? e.message : String(e)) }
  }, [])

  useEffect(() => {
    void refresh()
    const t = setInterval(() => void refresh(), 5000)
    return () => clearInterval(t)
  }, [refresh])

  const guard = async (fn: () => Promise<void>) => {
    try { await fn(); await refresh() }
    catch (e) { setError(e instanceof Error ? e.message : String(e)) }
  }

  const enroll = () => guard(async () => {
    if (!name.trim() || !address.trim()) throw new Error('name and address required')
    const res = await clusterEnroll(name, address, parseLabels(labels),
      sshHost || undefined, sshUser || undefined, sshPass || undefined, autoDeploy, manageMode)
    setTokens((t) => ({ ...t, [res.node.id]: res.token }))
    setName(''); setAddress(''); setSshHost('')
    setNotice(`Enrolled ${res.node.name}. Token: ${res.token}`)
  })

  const toggle = (id: string) => setSelected((s) => {
    const next = new Set(s); next.has(id) ? next.delete(id) : next.add(id); return next
  })

  const deploy = () => guard(async () => {
    if (selected.size === 0) throw new Error('select at least one node')
    // Pre-deploy lint: which external files does the config need, do we have them?
    const check = await clusterDeployCheck(config, Object.keys(bundleFiles))
    if (check.missing.length) {
      const ok = window.confirm(
        'Uyarı — bu config şu harici dosyalara bağımlı ve elimizde yok:\n  ' +
        check.missing.join('\n  ') +
        "\n\nHedef node'larda bu dosyalar yoksa deploy 'haproxy -c' ile başarısız olur." +
        "\nİpucu: önce kaynak node'da 'Fetch config' (📋) ile çekerseniz dosyalar da gelir." +
        '\n\nYine de devam edilsin mi?')
      if (!ok) { setNotice('Deploy iptal edildi.'); return }
    }
    // Ship only the files this config actually references (incl. cert dirs).
    const filesToSend: Record<string, string> = {}
    for (const [p, b64] of Object.entries(bundleFiles)) {
      if (check.file_refs.some((ref) => p === ref || (ref.endsWith('/') && p.startsWith(ref))))
        filesToSend[p] = b64
    }
    const res = await clusterDeploy(config, [...selected], true, filesToSend)
    const nf = Object.keys(filesToSend).length
    setNotice(`Deployed to ${res.deployments.length} node(s)` +
      (nf ? ` (+${nf} dosya: ${Object.keys(filesToSend).map(shortPath).join(', ')})` : '') +
      (res.skipped.length ? `, ${res.skipped.length} failed validation` : ''))
  })

  const checkIn = (id: string) => guard(async () => {
    const token = tokens[id]
    if (!token) throw new Error('token unknown (enroll in this session to simulate)')
    const node = nodes.find((n) => n.id === id)
    await agentHeartbeat(id, token, {
      agent_version: '1.0.0', haproxy_version: '2.8',
      config_version: node?.pending_version ?? null,
      config_hash: node?.pending_version ? `v${node.pending_version}` : 'init',
    })
  })

  const act = (id: string, actionType: string, params?: Record<string, string>) =>
    guard(async () => {
      await nodeAction(id, actionType, params ?? {})
      setNotice(`Action '${actionType}' queued — executes on next agent heartbeat`)
    })

  // Fetch the live config + its referenced files (certs/maps/errorfiles) from a
  // node into the editor. We queue the action and remember which node we asked
  // (and the timestamp of its last result) so the effect below adopts only the
  // fresh result for that node.
  const fetchConfig = (n: ClusterNode) => guard(async () => {
    const since = (n.last_action_result?._ts as number | undefined) ?? 0
    await nodeAction(n.id, 'config-bundle', {})
    setFetching({ id: n.id, since })
    setNotice(`Fetching config from ${n.name} — applies on next agent heartbeat`)
  })

  // Adopt a config-bundle result only once, only for the node we explicitly
  // asked, and only when it is newer than the request. This prevents the 5s
  // refresh loop from continuously overwriting the editor with a stale result.
  useEffect(() => {
    if (!fetching) return
    const n = nodes.find((x) => x.id === fetching.id)
    const r = n?.last_action_result
    if (!r || r.type !== 'config-bundle') return
    if (((r._ts as number | undefined) ?? 0) <= fetching.since) return
    if (r.ok && r.output && onConfigChange) {
      try {
        const bundle = JSON.parse(atob(r.output as string)) as
          { config: string; files: Record<string, string> }
        onConfigChange(atob(bundle.config))
        setBundleFiles(bundle.files || {})
        const fileNames = Object.keys(bundle.files || {})
        setNotice(`Config fetched from ${n!.name}` +
          (fileNames.length
            ? ` with ${fileNames.length} file(s): ${fileNames.map(shortPath).join(', ')}`
            : ' (no extra files)'))
      } catch { setError('failed to decode fetched config bundle') }
    } else if (!r.ok) {
      setError(`config-bundle failed on ${n!.name}: ${(r.error as string) ?? 'unknown error'}`)
    }
    setFetching(null)
  }, [nodes, fetching, onConfigChange])

  return (
    <div className="cluster-panel">
      {error && <p className="error">{error}</p>}
      {notice && <p className="notice">{notice}</p>}

      {overview && (
        <div className="cluster-overview">
          <span className="stat"><b>{overview.total}</b> nodes</span>
          <span className="stat on"><b>{overview.online}</b> online</span>
          <span className="stat off"><b>{overview.offline}</b> offline</span>
          <span className="stat pend"><b>{overview.pending}</b> pending</span>
          <span className="stat"><b>{overview.pending_deploys}</b> deploys in flight</span>
          {overview.distinct_config_hashes > 1 &&
            <span className="stat drift">⚠ config drift ({overview.distinct_config_hashes})</span>}
        </div>
      )}

      <div className="enroll-card">
        <div className="card-head">
          <h4>Add a node</h4>
          <small>Register a HAProxy host. Provide SSH details to auto-install the agent over SSH.</small>
        </div>
        <div className="field-grid">
          <label className="fld"><span>Name</span>
            <input placeholder="edge-1" value={name} onChange={(e) => setName(e.target.value)} /></label>
          <label className="fld"><span>Address</span>
            <input placeholder="192.168.1.10" value={address} onChange={(e) => setAddress(e.target.value)} /></label>
          <label className="fld"><span>Labels</span>
            <input placeholder="role=edge,env=prod" value={labels} onChange={(e) => setLabels(e.target.value)} /></label>
        </div>
        <div className="field-grid">
          <label className="fld"><span>SSH host</span>
            <input placeholder="for auto-install" value={sshHost} onChange={(e) => setSshHost(e.target.value)} /></label>
          <label className="fld"><span>SSH user</span>
            <input placeholder="root" value={sshUser} onChange={(e) => setSshUser(e.target.value)} /></label>
          <label className="fld"><span>SSH password</span>
            <input type="password" placeholder="••••••" value={sshPass} onChange={(e) => setSshPass(e.target.value)} /></label>
          <label className="fld"><span>Mode</span>
            <select value={manageMode} onChange={(e) => setManageMode(e.target.value)}>
              <option value="auto">auto-detect</option>
              <option value="systemd">systemd</option>
              <option value="docker">docker</option>
            </select></label>
        </div>
        <div className="enroll-foot">
          <label className="chk">
            <input type="checkbox" checked={autoDeploy} onChange={(e) => setAutoDeploy(e.target.checked)} />
            <span>Auto-install agent over SSH</span>
          </label>
          <button className="primary" onClick={enroll}>Enroll node</button>
        </div>
      </div>

      <div className="deploy-bar">
        <button className="primary" onClick={deploy} disabled={selected.size === 0}>
          ⬆ Deploy editor config{selected.size > 0 ? ` → ${selected.size} node(s)` : ''}
        </button>
        <small>Validates with <code>haproxy -c</code>, then pushes the editor config to the selected nodes.</small>
      </div>

      <div className="node-wrap">
        <table className="node-table">
          <thead>
            <tr><th></th><th>Node</th><th>Status</th><th>Service</th><th>HAProxy</th><th>Config</th>
              <th>Ver</th><th>Actions</th></tr>
          </thead>
          <tbody>
            {nodes.length === 0 && <tr><td colSpan={8} className="empty">No nodes enrolled yet.</td></tr>}
            {nodes.map((n) => (
              <tr key={n.id}>
                <td><input type="checkbox" checked={selected.has(n.id)} onChange={() => toggle(n.id)} /></td>
                <td>
                  <strong>{n.name}</strong>
                  <small>{n.address}</small>
                  {Object.entries(n.labels).map(([k, v]) => (
                    <span key={k} className="label">{k}={v}</span>
                  ))}
                </td>
                <td><span className="badge" style={{ '--dot': STATUS_COLOR[n.status] } as CSSProperties}>{n.status}</span></td>
                <td><span className="badge" style={{ '--dot': SVC_COLOR[n.service_status] ?? '#64748b' } as CSSProperties}>{n.service_status}</span></td>
                <td>{n.haproxy_version ?? '—'}</td>
                <td><code>{n.config_hash ?? '—'}</code></td>
                <td>{n.applied_version ?? '–'} / {n.pending_version ?? '–'}</td>
                <td className="node-actions">
                  <span className="act-group">
                    <button className="ico" onClick={() => act(n.id, 'restart')} title="Restart HAProxy">↻</button>
                    <button className="ico stop" onClick={() => act(n.id, 'stop')} title="Stop HAProxy">■</button>
                    <button className="ico start" onClick={() => act(n.id, 'start')} title="Start HAProxy">▶</button>
                  </span>
                  <button className="ico fetch" onClick={() => fetchConfig(n)} title="Fetch HAProxy config into the editor">📋</button>
                  {import.meta.env.DEV && tokens[n.id] &&
                    <button className="ico" onClick={() => checkIn(n.id)} title="DEV ONLY: simulate an agent heartbeat with fake version info">sim</button>}
                  <button className="ico" onClick={() => guard(() => clusterRollback(n.id).then(() => undefined))} title="Roll back to the previous config">↶</button>
                  <button className="ico danger" onClick={() => guard(() => clusterRemove(n.id))} title="Remove node">✕</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
