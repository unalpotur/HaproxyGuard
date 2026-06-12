import { useCallback, useState } from 'react'
import { fetchAnalysis, fetchTopology, type AnalysisResult, type TopologyGraph } from './api'
import TopologyView from './TopologyView'
import FindingsPanel from './FindingsPanel'
import FixBar from './FixBar'
import SslPanel from './SslPanel'
import SecurityPanel from './SecurityPanel'
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

type Tab = 'topology' | 'findings' | 'ssl' | 'security' | 'dashboard'

export default function App() {
  const [config, setConfig] = useState(SAMPLE)
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
            <button className={tab === 'dashboard' ? 'active' : ''} onClick={() => setTab('dashboard')}>
              Dashboard
            </button>
          </nav>
          <div className="panel">
            {error && <p className="error">{error}</p>}
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
            {!error && tab === 'dashboard' && <Dashboard />}
          </div>
        </section>
      </main>
    </div>
  )
}
