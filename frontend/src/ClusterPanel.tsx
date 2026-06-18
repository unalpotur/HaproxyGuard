import { Fragment, useCallback, useEffect, useState, type CSSProperties } from 'react'
import {
  clusterNodes, clusterOverview, clusterEnroll, clusterDeploy, clusterDeployCheck,
  clusterRollback, clusterRemove, agentHeartbeat, nodeAction,
  type ClusterNode, type ClusterOverview, type NodeCert,
} from './api'

const shortPath = (p: string) => p.split('/').pop() || p

const STATUS_COLOR: Record<string, string> = {
  online: '#16a34a', offline: '#dc2626', pending: '#ca8a04',
}
const SVC_COLOR: Record<string, string> = {
  running: '#16a34a', stopped: '#ef4444', unknown: '#64748b',
}

// Days-remaining → colour and label, matching the SSL manager thresholds.
const certColor = (d: number | null) =>
  d == null ? '#64748b' : d < 0 || d <= 7 ? '#dc2626' : d <= 30 ? '#ea580c' : '#16a34a'
const certLabel = (d: number | null) =>
  d == null ? '?' : d < 0 ? `${-d} gün önce doldu` : `${d} gün`

// Pull the cert-list result out of a node's last_action_result (if fresh).
function nodeCerts(n: ClusterNode): NodeCert[] | null {
  const r = n.last_action_result
  if (!r || r.type !== 'cert-list') return null
  if (!r.ok) return null
  try { return JSON.parse(r.output as string) as NodeCert[] } catch { return null }
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
  // Per-node certificate panel: which node is expanded + the issue-cert form.
  const [certFor, setCertFor] = useState<string | null>(null)
  const [cDomains, setCDomains] = useState('')
  const [cEmail, setCEmail] = useState('')
  const [cPem, setCPem] = useState('')
  const [cDry, setCDry] = useState(true)
  const [cForce, setCForce] = useState(false)

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

  const act = (id: string, actionType: string, params?: Record<string, unknown>) =>
    guard(async () => {
      await nodeAction(id, actionType, params ?? {})
      setNotice(`Action '${actionType}' queued — executes on next agent heartbeat`)
    })

  // Open the cert panel for a node and queue a cert-list refresh.
  const openCerts = (n: ClusterNode) => {
    setCertFor((cur) => (cur === n.id ? null : n.id))
    if (certFor !== n.id) void act(n.id, 'cert-list')
  }

  // Queue a Let's Encrypt issue/renew. dry_run is a real boolean.
  const issueCert = (n: ClusterNode) => guard(async () => {
    if (!cDomains.trim() || !cEmail.trim()) throw new Error('domain(s) and email required')
    await nodeAction(n.id, 'cert-issue', {
      domains: cDomains.trim(), email: cEmail.trim(),
      dry_run: cDry, force: cForce, pem_path: cPem.trim() || undefined,
    })
    setNotice(`cert-issue (${cDry ? 'dry-run' : 'GERÇEK'}) queued for ${cDomains} — sonuç bir sonraki heartbeat'te`)
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
              <Fragment key={n.id}>
              <tr>
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
                  <button className={`ico${certFor === n.id ? ' on' : ''}`} onClick={() => openCerts(n)} title="Sertifikalar (süre + Let's Encrypt)">🔐</button>
                  <button className="ico fetch" onClick={() => fetchConfig(n)} title="Fetch HAProxy config into the editor">📋</button>
                  {import.meta.env.DEV && tokens[n.id] &&
                    <button className="ico" onClick={() => checkIn(n.id)} title="DEV ONLY: simulate an agent heartbeat with fake version info">sim</button>}
                  <button className="ico" onClick={() => guard(() => clusterRollback(n.id).then(() => undefined))} title="Roll back to the previous config">↶</button>
                  <button className="ico danger" onClick={() => guard(() => clusterRemove(n.id))} title="Remove node">✕</button>
                </td>
              </tr>
              {certFor === n.id && (
                <tr className="cert-row"><td colSpan={8}>
                  <CertView node={n} onIssue={() => issueCert(n)}
                    domains={cDomains} setDomains={setCDomains}
                    email={cEmail} setEmail={setCEmail}
                    pem={cPem} setPem={setCPem} dry={cDry} setDry={setCDry}
                    force={cForce} setForce={setCForce} />
                </td></tr>
              )}
              </Fragment>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

type CertViewProps = {
  node: ClusterNode
  onIssue: () => void
  domains: string; setDomains: (v: string) => void
  email: string; setEmail: (v: string) => void
  pem: string; setPem: (v: string) => void
  dry: boolean; setDry: (v: boolean) => void
  force: boolean; setForce: (v: boolean) => void
}

function CertView(p: CertViewProps) {
  const certs = nodeCerts(p.node)
  const r = p.node.last_action_result
  const failed = r && r.type === 'cert-list' && !r.ok
  const issueResult = r && r.type === 'cert-issue' ? r : null

  return (
    <div className="cert-view">
      <h4>🔐 {p.node.name} — sertifikalar</h4>
      {issueResult && (
        <p className={issueResult.ok ? 'notice' : 'error'}>
          cert-issue {issueResult.ok ? '✓' : '✗'}: {String(issueResult.output ?? issueResult.error ?? '')}
        </p>
      )}
      {failed && <p className="error">cert-list başarısız: {String(r!.error ?? '')}</p>}
      {!certs && !failed && <p className="empty">Sertifika listesi bekleniyor — agent'ın bir sonraki heartbeat'inde gelir (~10 sn). Agent ≥ 2.4.0 olmalı.</p>}

      {certs && certs.length > 0 && (
        <table className="cert-table">
          <thead><tr><th>Domain</th><th>SAN</th><th>Veren (issuer)</th><th>Bitiş</th><th>Kalan</th><th>Dosya</th></tr></thead>
          <tbody>
            {certs.map((c) => (
              <tr key={c.path}>
                <td><strong>{c.subject_cn}</strong></td>
                <td><small>{c.sans.join(', ') || '—'}</small></td>
                <td>{c.issuer_cn}</td>
                <td>{c.not_after}</td>
                <td><span className="badge" style={{ '--dot': certColor(c.days_remaining) } as CSSProperties}>
                  {certLabel(c.days_remaining)}</span></td>
                <td><code>{shortPath(c.path)}</code></td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {certs && certs.length === 0 && <p className="empty">Bu node'da sertifika bulunamadı.</p>}

      <div className="cert-issue-form">
        <h5>Let's Encrypt ile sertifika al / yenile</h5>
        <div className="field-grid">
          <label className="fld"><span>Domain</span>
            <input placeholder="demo.nevalabs.com"
              value={p.domains} onChange={(e) => p.setDomains(e.target.value)} /></label>
          <label className="fld"><span>E-posta</span>
            <input placeholder="ops@nevalabs.com" value={p.email}
              onChange={(e) => p.setEmail(e.target.value)} /></label>
          <label className="fld"><span>Hedef .pem (ops.)</span>
            <input placeholder="/etc/ssl/demo.nevalabs.com.pem" value={p.pem}
              onChange={(e) => p.setPem(e.target.value)} /></label>
        </div>
        <div className="cert-issue-foot">
          <label className="chk">
            <input type="checkbox" checked={p.dry} onChange={(e) => p.setDry(e.target.checked)} />
            <span>Önce test et (dry-run) — sertifika almadan ACME akışını dener</span>
          </label>
          <label className="chk">
            <input type="checkbox" checked={p.force} onChange={(e) => p.setForce(e.target.checked)} />
            <span>Zorla yenile (süresi dolmamış olsa da)</span>
          </label>
          <button className={p.dry ? '' : 'primary'} onClick={p.onIssue}>
            {p.dry ? 'Dry-run dene' : 'Sertifikayı al (gerçek)'}
          </button>
        </div>
        <small className="cert-hint">
          Her sertifika ayrı bir <code>.pem</code> ise <strong>tek seferde tek domain</strong> gir
          (birden çok domain = tek SAN sertifikası). Boş bırakırsan <code>.pem</code> hedefi
          <code>CERT_DIR/&lt;domain&gt;.pem</code> olur — 121 gibi <code>/etc/ssl</code> kullanan
          kurulumlarda hedef yolu elle ver. certbot node'da kurulu ve challenge yönlendirmesi
          ayarlı olmalı. Başarılıysa agent fullchain+key'i .pem'e yazıp HAProxy'yi reload eder.
        </small>
      </div>
    </div>
  )
}
