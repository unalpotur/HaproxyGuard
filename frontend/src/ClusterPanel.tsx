import { useCallback, useEffect, useState } from 'react'
import {
  clusterNodes, clusterOverview, clusterEnroll, clusterDeploy, clusterRollback,
  clusterRemove, agentHeartbeat, nodeAction,
  type ClusterNode, type ClusterOverview,
} from './api'

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
    const res = await clusterDeploy(config, [...selected], true)
    setNotice(`Deployed to ${res.deployments.length} node(s)` +
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

  // Fetch the live config from a specific node into the editor. We queue the
  // action and remember which node we asked (and the timestamp of its last
  // result) so the effect below adopts only the fresh result for that node.
  const fetchConfig = (n: ClusterNode) => guard(async () => {
    const since = (n.last_action_result?._ts as number | undefined) ?? 0
    await nodeAction(n.id, 'config-get', {})
    setFetching({ id: n.id, since })
    setNotice(`Fetching config from ${n.name} — applies on next agent heartbeat`)
  })

  // Adopt a config-get result only once, only for the node we explicitly asked,
  // and only when it is newer than the request. This prevents the 5s refresh
  // loop from continuously overwriting the editor with a stale result.
  useEffect(() => {
    if (!fetching) return
    const n = nodes.find((x) => x.id === fetching.id)
    const r = n?.last_action_result
    if (!r || r.type !== 'config-get') return
    if (((r._ts as number | undefined) ?? 0) <= fetching.since) return
    if (r.ok && r.output && onConfigChange) {
      try {
        onConfigChange(atob(r.output as string))
        setNotice(`Config fetched from ${n!.name} into the editor`)
      } catch { setError('failed to decode fetched config') }
    } else if (!r.ok) {
      setError(`config-get failed on ${n!.name}: ${(r.error as string) ?? 'unknown error'}`)
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

      <div className="enroll-row">
        <input placeholder="name" value={name} onChange={(e) => setName(e.target.value)} />
        <input placeholder="address" value={address}
               onChange={(e) => setAddress(e.target.value)} />
        <input placeholder="labels k=v,k=v" value={labels}
               onChange={(e) => setLabels(e.target.value)} />
        <input placeholder="SSH host (IP)" value={sshHost}
               onChange={(e) => setSshHost(e.target.value)} />
        <input placeholder="SSH user" value={sshUser}
               onChange={(e) => setSshUser(e.target.value)} size={8} />
        <input placeholder="SSH pass" value={sshPass} type="password"
               onChange={(e) => setSshPass(e.target.value)} size={12} />
        <label><input type="checkbox" checked={autoDeploy}
               onChange={(e) => setAutoDeploy(e.target.checked)} /> auto-deploy</label>
        <select value={manageMode} onChange={(e) => setManageMode(e.target.value)}
                style={{ width: 80, marginLeft: 4 }}>
          <option value="auto">auto</option>
          <option value="systemd">systemd</option>
          <option value="docker">docker</option>
        </select>
        <button onClick={enroll}>Enroll node</button>
      </div>

      <div className="cluster-actions">
        <button onClick={deploy} disabled={selected.size === 0}>
          Deploy current config → {selected.size} selected
        </button>
        <small>Pushes the editor config (validated with <code>haproxy -c</code>) to selected nodes.</small>
      </div>

      <table className="node-table">
        <thead>
          <tr><th></th><th>Node</th><th>Agent</th><th>HAProxy</th><th>Version</th><th>Config</th>
            <th>Ver</th><th>Actions</th></tr>
        </thead>
        <tbody>
          {nodes.length === 0 && <tr><td colSpan={8} className="empty">No nodes enrolled yet.</td></tr>}
          {nodes.map((n) => (
            <tr key={n.id}>
              <td><input type="checkbox" checked={selected.has(n.id)} onChange={() => toggle(n.id)} /></td>
              <td>
                <strong>{n.name}</strong><br />
                <small>{n.address}</small>
                {Object.entries(n.labels).map(([k, v]) => (
                  <span key={k} className="label">{k}={v}</span>
                ))}
              </td>
              <td><span className="badge" style={{ background: STATUS_COLOR[n.status] }}>{n.status}</span></td>
              <td><span className="badge" style={{ background: SVC_COLOR[n.service_status] ?? '#64748b' }}>{n.service_status}</span></td>
              <td>{n.haproxy_version ?? '—'}</td>
              <td><code>{n.config_hash ?? '—'}</code></td>
              <td>{n.applied_version ?? '–'} / {n.pending_version ?? '–'}</td>
              <td className="node-actions">
                <button onClick={() => act(n.id, 'restart')} title="Restart HAProxy">↻</button>
                <button onClick={() => act(n.id, 'stop')} title="Stop HAProxy">■</button>
                <button onClick={() => act(n.id, 'start')} title="Start HAProxy">▶</button>
                <button onClick={() => fetchConfig(n)} title="Fetch HAProxy config from node">📋</button>
                {import.meta.env.DEV && tokens[n.id] &&
                  <button onClick={() => checkIn(n.id)} title="DEV ONLY: simulate an agent heartbeat with fake version info">Check in</button>}
                <button onClick={() => guard(() => clusterRollback(n.id).then(() => undefined))}>Rollback</button>
                <button className="warn" onClick={() => guard(() => clusterRemove(n.id))}>✕</button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
