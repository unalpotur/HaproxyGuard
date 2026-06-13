import { useCallback, useState } from 'react'
import { fetchAnalysis, fetchTopology, loadLocalConfig, type AnalysisResult, type TopologyGraph } from './api'
import TopologyView from './TopologyView'
import FindingsPanel from './FindingsPanel'
import FixBar from './FixBar'
import SslPanel from './SslPanel'
import SecurityPanel from './SecurityPanel'
import AssistantPanel from './AssistantPanel'
import ClusterPanel from './ClusterPanel'
import BuilderPanel from './BuilderPanel'
import AlertsPanel from './AlertsPanel'
import AuditPanel from './AuditPanel'
import VersionsPanel from './VersionsPanel'
import Dashboard from './Dashboard'
import './App.css'

const SAMPLE = `frontend web
    bind *:80
    bind *:443 ssl crt /etc/haproxy/certs/site.pem ssl-min-ver TLSv1.2
    acl is_api path_beg /api
    use_backend api_servers if is_api
    default_backend web_servers

backend web_servers
    balance roundrobin
    option httpchk GET /healthz
    server web1 10.0.0.11:8080 check
    server web2 10.0.0.12:8080 check

backend api_servers
    server api1 10.0.1.11:9000 check
`

type Tab = 'builder' | 'topology' | 'findings' | 'ssl' | 'security' | 'assistant' | 'cluster' | 'alerts' | 'audit' | 'versions' | 'dashboard'

export default function App() {
  const [config, setConfig] = useState(SAMPLE)
  const [logs, setLogs] = useState('')
  const [graph, setGraph] = useState<TopologyGraph | null>(null)
  const [analysis, setAnalysis] = useState<AnalysisResult | null>(null)
  const [tab, setTab] = useState<Tab>('topology')
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)

  const run = useCallback(async (override?: string) => {
    const text = override ?? config
    setLoading(true)
    setError(null)
    try {
      const [g, a] = await Promise.all([fetchTopology(text), fetchAnalysis(text)])
      setGraph(g)
      setAnalysis(a)
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setLoading(false)
    }
  }, [config])

  const issueCount = analysis?.findings.length ?? 0

  return (
    <div className="layout">
      <header>
        <h1>HAProxy Guard</h1>
        <input
          type="password" placeholder="API key"
          defaultValue={localStorage.getItem('hg_api_key') ?? ''}
          onChange={(e) => localStorage.setItem('hg_api_key', e.target.value)}
          style={{ width: 140, marginRight: 8 }}
          title="HG_ADMIN_KEY for RBAC"
        />
        <button
          onClick={() => loadLocalConfig()
            .then((r) => { setConfig(r.content); void run(r.content) })
            .catch((e) => setError(e instanceof Error ? e.message : String(e)))}
          title="Read /etc/haproxy/haproxy.cfg from the API host"
        >
          Load server config
        </button>
        <button onClick={() => run()} disabled={loading}>
          {loading ? 'Analyzing…' : 'Parse & Analyze'}
        </button>
      </header>
      <main>
        <section className="editor">
          <textarea
            value={config}
            onChange={(e) => setConfig(e.target.value)}
            spellCheck={false}
            placeholder="Paste your haproxy.cfg here…"
          />
        </section>
        <section className="results">
          <nav>
            <button className={tab === 'builder' ? 'active' : ''} onClick={() => setTab('builder')}>
              Builder
            </button>
            <button className={tab === 'topology' ? 'active' : ''} onClick={() => setTab('topology')}>
              Topology
            </button>
            <button className={tab === 'findings' ? 'active' : ''} onClick={() => setTab('findings')}>
              Findings{analysis ? ` (${issueCount})` : ''}
            </button>
            <button className={tab === 'ssl' ? 'active' : ''} onClick={() => setTab('ssl')}>
              SSL
            </button>
            <button className={tab === 'security' ? 'active' : ''} onClick={() => setTab('security')}>
              Security
            </button>
            <button className={tab === 'assistant' ? 'active' : ''} onClick={() => setTab('assistant')}>
              Assistant
            </button>
            <button className={tab === 'cluster' ? 'active' : ''} onClick={() => setTab('cluster')}>
              Cluster
            </button>
            <button className={tab === 'alerts' ? 'active' : ''} onClick={() => setTab('alerts')}>
              Alerts
            </button>
            <button className={tab === 'audit' ? 'active' : ''} onClick={() => setTab('audit')}>
              Audit
            </button>
            <button className={tab === 'versions' ? 'active' : ''} onClick={() => setTab('versions')}>
              Versions
            </button>
            <button className={tab === 'dashboard' ? 'active' : ''} onClick={() => setTab('dashboard')}>
              Dashboard
            </button>
          </nav>
          <div className="panel">
            {error && <p className="error">{error}</p>}
            {!error && tab === 'builder' && (
              <BuilderPanel config={config}
                onApply={(c, go) => { setConfig(c); void run(c); if (go) setTab('cluster') }} />
            )}
            {!error && tab === 'topology' && (graph ? <TopologyView graph={graph} /> : <p className="empty">Click “Parse &amp; Analyze” to render the topology.</p>)}
            {!error && tab === 'findings' && (analysis ? (
              <>
                <FixBar
                  config={config}
                  result={analysis}
                  onContentChange={(c) => { setConfig(c); void run(c) }}
                />
                <FindingsPanel result={analysis} />
              </>
            ) : <p className="empty">No analysis yet.</p>)}
            {!error && tab === 'ssl' && <SslPanel config={config} />}
            {!error && tab === 'security' && <SecurityPanel config={config} />}
            {!error && tab === 'assistant' && <AssistantPanel config={config} />}
            {!error && tab === 'cluster' && <ClusterPanel config={config} onConfigChange={(c) => { setConfig(c) }} />}
            {!error && tab === 'alerts' && (
              <>
                <textarea
                  className="log-input"
                  value={logs}
                  onChange={(e) => setLogs(e.target.value)}
                  placeholder="Paste HAProxy access logs here (optional)…"
                  rows={6}
                />
                <AlertsPanel config={config} logs={logs || undefined} />
              </>
            )}
            {!error && tab === 'audit' && <AuditPanel />}
            {!error && tab === 'versions' && (
              <VersionsPanel config={config} onRestore={(c) => { setConfig(c); void run(c) }} />
            )}
            {!error && tab === 'dashboard' && <Dashboard />}
          </div>
        </section>
      </main>
    </div>
  )
}
