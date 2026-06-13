import { useCallback, useEffect, useRef, useState } from 'react'
import { clusterNodes, clusterOverview, type ClusterNode, type ClusterOverview } from './api'

const NODE_STATUS_COLOR: Record<string, string> = {
  online: '#22c55e', offline: '#ef4444', pending: '#f59e0b',
}
const NODE_SVC_COLOR: Record<string, string> = {
  running: '#22c55e', stopped: '#ef4444', unknown: '#64748b',
}

function ClusterNodesCard() {
  const [nodes, setNodes] = useState<ClusterNode[]>([])
  const [ov, setOv] = useState<ClusterOverview | null>(null)
  const [err, setErr] = useState<string | null>(null)

  useEffect(() => {
    const load = async () => {
      try {
        const [n, o] = await Promise.all([clusterNodes(), clusterOverview()])
        setNodes(n); setOv(o); setErr(null)
      } catch (e) { setErr(e instanceof Error ? e.message : String(e)) }
    }
    void load()
    const t = setInterval(() => void load(), 5000)
    return () => clearInterval(t)
  }, [])

  return (
    <>
      <div className="dash-card">
        <div className="dash-card-head">
          <h4>Cluster nodes</h4>
          {ov && (
            <div className="cluster-overview">
              <span className="stat"><b>{ov.total}</b> total</span>
              <span className="stat on"><b>{ov.online}</b> online</span>
              <span className="stat off"><b>{ov.offline}</b> offline</span>
              <span className="stat pend"><b>{ov.pending}</b> pending</span>
            </div>
          )}
        </div>
        {err && <p className="error-inline">{err}</p>}
        {!err && nodes.length === 0 && <p className="empty" style={{ padding: 12 }}>No nodes enrolled yet.</p>}
        {nodes.length > 0 && (
          <div className="node-grid">
            {nodes.map((n) => (
              <div className={`node-card ${n.status}`} key={n.id}>
                <div className="node-card-top">
                  <span className="dot" style={{ background: NODE_STATUS_COLOR[n.status] ?? '#64748b' }} />
                  <strong>{n.name}</strong>
                  <span className="node-card-status">{n.status}</span>
                </div>
                <small className="node-card-addr">{n.address}</small>
                <div className="node-card-meta">
                  <span>HAProxy <b>{n.haproxy_version ?? '—'}</b></span>
                  <span>agent <b>{n.agent_version ?? '—'}</b></span>
                  <span>
                    svc <b style={{ color: NODE_SVC_COLOR[n.service_status] ?? '#94a3b8' }}>{n.service_status}</b>
                  </span>
                  <span>ver <b>{n.applied_version ?? '–'}/{n.pending_version ?? '–'}</b></span>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Per-node live metrics, collected by each agent from its local HAProxy */}
      {nodes.map((n) => {
        const stat = (n.metrics as { stat?: StatRow[] } | undefined)?.stat
        const rows = (stat ?? []).filter((r) => r.svname === 'FRONTEND' || r.svname === 'BACKEND')
        if (rows.length === 0) return null
        return (
          <div className="dash-card" key={`m-${n.id}`}>
            <div className="dash-card-head">
              <h4>{n.name} · live metrics</h4>
              <small>{n.address} · {rows.length} proxies</small>
            </div>
            <table>
              <thead>
                <tr><th>Proxy</th><th>Type</th><th>Status</th><th>Sessions</th>
                  <th>Rate</th><th>2xx</th><th>4xx</th><th>5xx</th><th>rtime</th></tr>
              </thead>
              <tbody>
                {rows.map((r, i) => (
                  <tr key={`${r.pxname}-${r.svname}-${i}`}>
                    <td>{r.pxname}</td>
                    <td>{r.svname}</td>
                    <td><span className="dot" style={{ background: STATUS_COLOR(r.status) }} /> {r.status}</td>
                    <td>{r.scur}</td>
                    <td>{r.rate || r.req_rate}</td>
                    <td>{r.hrsp_2xx}</td>
                    <td>{r.hrsp_4xx}</td>
                    <td className={Number(r.hrsp_5xx) > 0 ? 'warn' : ''}>{r.hrsp_5xx}</td>
                    <td>{r.rtime ? `${r.rtime}ms` : '–'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )
      })}
    </>
  )
}

interface StatRow {
  pxname: string
  svname: string
  type: string
  status: string
  scur: string
  rate: string
  req_rate: string
  hrsp_2xx: string
  hrsp_4xx: string
  hrsp_5xx: string
  rtime: string
  check_status: string
}

interface Snapshot {
  timestamp: number
  ok: boolean
  error?: string
  rows: StatRow[]
}

const STATUS_COLOR = (s: string) =>
  s.startsWith('UP') || s === 'OPEN' ? '#22c55e'
  : s.startsWith('DOWN') ? '#ef4444'
  : s === 'no check' ? '#64748b'
  : '#eab308'

const TOKEN_KEY = 'hg_ws_token'

function Sparkline({ values }: { values: number[] }) {
  if (values.length < 2) return null
  const max = Math.max(...values, 1)
  const pts = values
    .map((v, i) => `${(i / (values.length - 1)) * 100},${28 - (v / max) * 26}`)
    .join(' ')
  return (
    <svg width="100" height="30" viewBox="0 0 100 30" preserveAspectRatio="none">
      <polyline points={pts} fill="none" stroke="#60a5fa" strokeWidth="1.5" />
    </svg>
  )
}

export default function Dashboard() {
  const [snapshot, setSnapshot] = useState<Snapshot | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [connected, setConnected] = useState(false)
  const [token, setToken] = useState(() => localStorage.getItem(TOKEN_KEY) ?? '')
  const [needToken, setNeedToken] = useState(false)
  const historyRef = useRef<Map<string, number[]>>(new Map())
  const wsRef = useRef<WebSocket | null>(null)

  const connect = useCallback(() => {
    wsRef.current?.close()
    setConnected(false)
    setError(null)

    const proto = location.protocol === 'https:' ? 'wss' : 'ws'
    const qs = token ? `?token=${encodeURIComponent(token)}` : ''
    const ws = new WebSocket(`${proto}://${location.host}/api/ws/metrics${qs}`)
    wsRef.current = ws

    ws.onopen = () => { setConnected(true); setNeedToken(false) }
    ws.onclose = () => setConnected(false)
    ws.onerror = () => setError('WebSocket connection failed — is the backend running with HAPROXY_STATS_ADDR set?')
    ws.onmessage = (ev) => {
      const snap: Snapshot = JSON.parse(ev.data)
      if (snap.ok === false && !snap.rows) {
        const msg = snap.error ?? 'metrics unavailable'
        setError(msg)
        if (msg.includes('Authentication') || msg.includes('token')) setNeedToken(true)
        return
      }
      setError(snap.ok ? null : snap.error ?? null)
      const hist = historyRef.current
      for (const row of snap.rows ?? []) {
        const key = `${row.pxname}/${row.svname}`
        const arr = hist.get(key) ?? []
        arr.push(Number(row.rate || row.req_rate || 0))
        if (arr.length > 60) arr.shift()
        hist.set(key, arr)
      }
      setSnapshot(snap)
    }
  }, [token])

  useEffect(() => { connect(); return () => wsRef.current?.close() }, [connect])

  const saveToken = (v: string) => {
    setToken(v)
    localStorage.setItem(TOKEN_KEY, v)
  }

  const metricsBody = () => {
    if (needToken) {
      return (
        <div style={{ padding: 12 }}>
          <p>RBAC aktif — WebSocket'a bağlanmak için API token gerekli.</p>
          <p style={{ color: '#64748b' }}>HG_ADMIN_KEY ile aynı değeri girin, veya Admin panelinden bir token oluşturun.</p>
          <div style={{ display: 'flex', gap: 8, marginTop: 8 }}>
            <input
              type="password" value={token} autoFocus
              onChange={(e) => saveToken(e.target.value)}
              placeholder="API token…"
              style={{ flex: 1 }}
            />
            <button onClick={connect}>Bağlan</button>
          </div>
        </div>
      )
    }
    if (error && !snapshot?.rows?.length) return <p className="error-inline" style={{ padding: 12 }}>{error}</p>
    if (!snapshot) return <p className="empty" style={{ padding: 12 }}>{connected ? 'Waiting for first snapshot…' : 'Connecting…'}</p>

    const rows = snapshot.rows.filter((r) => r.svname === 'FRONTEND' || r.svname === 'BACKEND' || r.type === '2')
    return (
      <>
        <div className="dash-status">
          <span className="badge" style={{ background: connected ? '#16a34a' : '#dc2626' }}>
            {connected ? 'live' : 'disconnected'}
          </span>
          <small>{new Date(snapshot.timestamp * 1000).toLocaleTimeString()}</small>
          {error && <span className="error-inline">{error}</span>}
          {token && (
            <button className="ghost" onClick={() => { saveToken(''); setNeedToken(false) }} title="Clear token"
                    style={{ padding: '2px 8px' }}>✕</button>
          )}
        </div>
        <table>
          <thead>
            <tr>
              <th>Proxy</th><th>Member</th><th>Status</th><th>Sessions</th>
              <th>Rate</th><th>Rate (60s)</th><th>2xx</th><th>4xx</th><th>5xx</th><th>rtime</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => {
              const key = `${r.pxname}/${r.svname}`
              return (
                <tr key={key}>
                  <td>{r.pxname}</td>
                  <td>{r.svname}</td>
                  <td><span className="dot" style={{ background: STATUS_COLOR(r.status) }} /> {r.status}</td>
                  <td>{r.scur}</td>
                  <td>{r.rate || r.req_rate}</td>
                  <td><Sparkline values={historyRef.current.get(key) ?? []} /></td>
                  <td>{r.hrsp_2xx}</td>
                  <td>{r.hrsp_4xx}</td>
                  <td className={Number(r.hrsp_5xx) > 0 ? 'warn' : ''}>{r.hrsp_5xx}</td>
                  <td>{r.rtime ? `${r.rtime}ms` : '–'}</td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </>
    )
  }

  return (
    <div className="dashboard">
      <ClusterNodesCard />
      <div className="dash-card">
        <div className="dash-card-head"><h4>Control plane HAProxy</h4>
          <small>local stats socket (HAPROXY_STATS_ADDR)</small></div>
        {metricsBody()}
      </div>
    </div>
  )
}
