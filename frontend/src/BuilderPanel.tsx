import { useMemo, useState } from 'react'

// A section-preserving HAProxy config builder. It models the parts people edit
// most (ports/binds, servers, routing) as form fields, but keeps EVERY other
// line verbatim per section — so loading a real config and saving it back is
// lossless: multiple frontends, listen blocks, SSL binds, map routing and any
// directive the form doesn't model are all preserved.

interface Bind { arg: string }                       // text after "bind "
interface Srv { name: string; addr: string; opts: string }  // addr = ip:port
interface Rule { path: string; backend: string }     // path_beg -> backend (create helper)
type Kind = 'global' | 'defaults' | 'frontend' | 'backend' | 'listen'

interface Section {
  id: number
  kind: Kind
  name: string
  binds: Bind[]
  rules: Rule[]
  defaultBackend: string
  balance: string
  servers: Srv[]
  rest: string          // every other body line, verbatim (newline-joined)
}

const HELP = {
  kind: 'frontend: istemcilerin bağlandığı giriş. backend: sunucu havuzu. listen: ikisi bir arada (ör. stats sayfası). global/defaults: genel ayarlar.',
  bind: 'Dinlenecek adres:port ve seçenekleri. Örn: *:80  ·  *:443 ssl crt /etc/haproxy/certs/site.pem',
  balance: 'Yük dağıtımı: roundrobin sırayla, leastconn en az meşgule, source aynı istemciyi aynı sunucuya.',
  server: 'Havuzdaki gerçek sunucu. Ad, adres (ip:port) ve seçenekler (ör. check). Örn: app1 · 10.0.0.5:8080 · check',
  defaultBackend: 'Hiçbir kurala uymayan trafiğin gideceği varsayılan havuz.',
  rule: 'Yola göre yönlendirme: /api ile başlayanları seçtiğin havuza gönderir (acl + use_backend üretir).',
  rest: 'Bu bölümün formda modellenmeyen tüm diğer satırları (timeout, option, http-request, map ile use_backend, stats, vb.). Aynen korunur ve yeniden yazılır — istersen elle düzenleyebilirsin.',
}

const KINDS: Kind[] = ['global', 'defaults', 'frontend', 'backend', 'listen']
const BALANCES = ['', 'roundrobin', 'leastconn', 'source', 'static-rr']
const hasBinds = (k: Kind) => k === 'frontend' || k === 'listen'
const hasServers = (k: Kind) => k === 'backend' || k === 'listen'

const Info = ({ t }: { t: string }) => <span className="info" title={t}>i</span>

let _seq = 0
const newSection = (kind: Kind, name = ''): Section => ({
  id: ++_seq, kind, name, binds: [], rules: [], defaultBackend: '', balance: '', servers: [], rest: '',
})

function defaultSections(): Section[] {
  const g = newSection('global'); g.rest = 'log /dev/log local0\nmaxconn 4096'
  const d = newSection('defaults')
  d.rest = 'mode http\nlog global\noption httplog\ntimeout connect 5s\ntimeout client  30s\ntimeout server  30s'
  const fe = newSection('frontend', 'web'); fe.binds = [{ arg: '*:80' }]; fe.defaultBackend = 'app'
  const be = newSection('backend', 'app'); be.balance = 'roundrobin'
  be.servers = [{ name: 'app1', addr: '', opts: 'check' }]
  return [g, d, fe, be]
}

// ── parse an existing config into the section model (lossless) ────────────
function parseConfig(text: string): Section[] {
  const sections: Section[] = []
  let cur: Section | null = null
  let rest: string[] = []
  const flush = () => { if (cur) { cur.rest = rest.join('\n'); sections.push(cur) } rest = [] }

  for (const raw of text.split('\n')) {
    const t = raw.trim()
    const head = t.match(/^(global|defaults|frontend|backend|listen)\b\s*(\S*)/)
    if (head) {
      flush()
      cur = newSection(head[1] as Kind, head[2] || '')
      continue
    }
    if (!cur || !t) continue
    let m: RegExpMatchArray | null
    if (hasBinds(cur.kind) && (m = t.match(/^bind\s+(.+)$/))) {
      cur.binds.push({ arg: m[1] })
    } else if (hasServers(cur.kind) && (m = t.match(/^server\s+(\S+)\s+(\S+)\s*(.*)$/))) {
      cur.servers.push({ name: m[1], addr: m[2], opts: m[3] })
    } else if (hasServers(cur.kind) && (m = t.match(/^balance\s+(.+)$/))) {
      cur.balance = m[1]
    } else if (hasBinds(cur.kind) && (m = t.match(/^default_backend\s+(.+)$/))) {
      cur.defaultBackend = m[1]
    } else {
      rest.push(t)  // verbatim — nothing is dropped
    }
  }
  flush()
  return sections.length ? sections : defaultSections()
}

// ── generate config text from the section model ──────────────────────────
function generate(sections: Section[]): string {
  const out: string[] = []
  for (const s of sections) {
    out.push(`${s.kind}${s.name ? ' ' + s.name : ''}`)
    if (hasBinds(s.kind)) for (const b of s.binds) if (b.arg.trim()) out.push(`    bind ${b.arg.trim()}`)
    if (hasServers(s.kind) && s.balance.trim()) out.push(`    balance ${s.balance.trim()}`)
    if (hasBinds(s.kind)) s.rules.forEach((r, i) => {
      if (r.path.trim() && r.backend) {
        out.push(`    acl b${s.id}r${i} path_beg ${r.path.trim()}`)
        out.push(`    use_backend ${r.backend} if b${s.id}r${i}`)
      }
    })
    if (hasServers(s.kind)) for (const v of s.servers) if (v.addr.trim())
      out.push(`    server ${v.name || 'srv'} ${v.addr.trim()}${v.opts.trim() ? ' ' + v.opts.trim() : ''}`)
    for (const line of s.rest.split('\n')) if (line.trim()) out.push(`    ${line.trim()}`)
    if (hasBinds(s.kind) && s.defaultBackend.trim()) out.push(`    default_backend ${s.defaultBackend.trim()}`)
    out.push('')
  }
  return out.join('\n').replace(/\n+$/, '\n')
}

export default function BuilderPanel({ config, onApply }:
  { config: string; onApply: (content: string, goCluster?: boolean) => void }) {
  const [sections, setSections] = useState<Section[]>(defaultSections)
  const [info, setInfo] = useState<string | null>(null)

  const patch = (id: number, p: Partial<Section>) =>
    setSections((ss) => ss.map((s) => (s.id === id ? { ...s, ...p } : s)))
  const removeSection = (id: number) => setSections((ss) => ss.filter((s) => s.id !== id))
  const addSection = (kind: Kind) =>
    setSections((ss) => [...ss, newSection(kind, kind === 'frontend' ? 'fe' : kind === 'backend' ? 'pool' : '')])

  const loadFromEditor = () => {
    const parsed = parseConfig(config)
    setSections(parsed)
    const by = (k: Kind) => parsed.filter((s) => s.kind === k).length
    setInfo(`Yüklendi: ${by('frontend')} frontend, ${by('backend')} backend, ${by('listen')} listen. ` +
      'Tüm satırlar korunuyor — modellenmeyenler her bölümün "Diğer satırlar" alanında.')
  }

  const backendNames = sections.filter((s) => hasServers(s.kind) && s.name).map((s) => s.name)
  const generated = useMemo(() => generate(sections), [sections])
  const ready = sections.length > 0

  return (
    <div className="builder">
      <div className="builder-intro">
        <div className="builder-intro-top">
          <span>
            Her bölümü düzenleyin; port/sunucu gibi sık değişenler form alanı, gerisi <b>aynen korunur</b>.
            Alanların yanındaki <span className="info" style={{ margin: '0 4px' }}>i</span> simgesine gelin.
            Bitince <b>Editöre yaz</b> deyip <b>Cluster</b>’dan deploy edin.
          </span>
          <button className="ghost" onClick={loadFromEditor} title="Editördeki mevcut config'i forma yükle">
            ⤓ Editörden yükle
          </button>
        </div>
      </div>

      {info && (
        <div className="builder-import ok">
          <span>✓ {info}</span>
          <button className="ghost" onClick={() => setInfo(null)}>kapat</button>
        </div>
      )}

      {sections.map((s) => (
        <div className={`builder-card bsection ${s.kind}`} key={s.id}>
          <div className="bsection-head">
            <select value={s.kind} onChange={(e) => patch(s.id, { kind: e.target.value as Kind })}
                    className={`kind-badge ${s.kind}`} title={HELP.kind}>
              {KINDS.map((k) => <option key={k} value={k}>{k}</option>)}
            </select>
            {s.kind !== 'global' && s.kind !== 'defaults' && (
              <input className="bsection-name" placeholder="ad" value={s.name}
                     onChange={(e) => patch(s.id, { name: e.target.value })} />
            )}
            <button className="ico danger" title="Bölümü sil" onClick={() => removeSection(s.id)}>✕</button>
          </div>

          {hasBinds(s.kind) && (
            <div className="bgroup">
              <div className="bgroup-head">Bind (dinlenen) <Info t={HELP.bind} /></div>
              {s.binds.map((b, i) => (
                <div className="line-row" key={i}>
                  <input className="grow" placeholder="*:80  veya  *:443 ssl crt /etc/haproxy/certs/x.pem"
                         value={b.arg}
                         onChange={(e) => patch(s.id, { binds: s.binds.map((x, j) => j === i ? { arg: e.target.value } : x) })} />
                  <button className="ico" title="Sil" onClick={() => patch(s.id, { binds: s.binds.filter((_, j) => j !== i) })}>−</button>
                </div>
              ))}
              <button className="ghost add" onClick={() => patch(s.id, { binds: [...s.binds, { arg: '' }] })}>+ bind</button>
            </div>
          )}

          {hasServers(s.kind) && (
            <div className="bgroup">
              <div className="bgroup-head">
                Dağıtım <Info t={HELP.balance} />
                <select value={s.balance} onChange={(e) => patch(s.id, { balance: e.target.value })}
                        style={{ marginLeft: 8, width: 150 }}>
                  {BALANCES.map((x) => <option key={x} value={x}>{x || '(belirtme)'}</option>)}
                </select>
              </div>
              <div className="bgroup-head" style={{ marginTop: 8 }}>Sunucular <Info t={HELP.server} /></div>
              {s.servers.map((v, i) => {
                const setSrv = (p: Partial<Srv>) =>
                  patch(s.id, { servers: s.servers.map((x, j) => j === i ? { ...x, ...p } : x) })
                return (
                  <div className="line-row" key={i}>
                    <input className="srv-name" placeholder="ad" value={v.name} onChange={(e) => setSrv({ name: e.target.value })} />
                    <input className="srv-addr" placeholder="10.0.0.5:8080" value={v.addr} onChange={(e) => setSrv({ addr: e.target.value })} />
                    <input className="srv-opts" placeholder="check" value={v.opts} onChange={(e) => setSrv({ opts: e.target.value })} />
                    <button className="ico" title="Sil" onClick={() => patch(s.id, { servers: s.servers.filter((_, j) => j !== i) })}>−</button>
                  </div>
                )
              })}
              <button className="ghost add" onClick={() => patch(s.id, { servers: [...s.servers, { name: `srv${s.servers.length + 1}`, addr: '', opts: 'check' }] })}>+ sunucu</button>
            </div>
          )}

          {hasBinds(s.kind) && (
            <div className="bgroup">
              <div className="bgroup-head">Yönlendirme kuralları <Info t={HELP.rule} /></div>
              {s.rules.map((r, i) => {
                const setRule = (p: Partial<Rule>) =>
                  patch(s.id, { rules: s.rules.map((x, j) => j === i ? { ...x, ...p } : x) })
                return (
                  <div className="line-row" key={i}>
                    <span className="rl">Yol</span>
                    <input className="path" placeholder="/api" value={r.path} onChange={(e) => setRule({ path: e.target.value })} />
                    <span className="rl">→</span>
                    <select value={r.backend} onChange={(e) => setRule({ backend: e.target.value })}>
                      <option value="">(havuz seç)</option>
                      {backendNames.map((b) => <option key={b} value={b}>{b}</option>)}
                    </select>
                    <button className="ico" title="Sil" onClick={() => patch(s.id, { rules: s.rules.filter((_, j) => j !== i) })}>−</button>
                  </div>
                )
              })}
              <button className="ghost add" onClick={() => patch(s.id, { rules: [...s.rules, { path: '/', backend: '' }] })}>+ kural</button>
              <div className="line-row" style={{ marginTop: 8 }}>
                <span className="rl">Varsayılan havuz <Info t={HELP.defaultBackend} /></span>
                <select value={s.defaultBackend} onChange={(e) => patch(s.id, { defaultBackend: e.target.value })}>
                  <option value="">(yok)</option>
                  {backendNames.map((b) => <option key={b} value={b}>{b}</option>)}
                  {s.defaultBackend && !backendNames.includes(s.defaultBackend) &&
                    <option value={s.defaultBackend}>{s.defaultBackend}</option>}
                </select>
              </div>
            </div>
          )}

          <details className="bgroup raw">
            <summary>Diğer satırlar (gelişmiş) <Info t={HELP.rest} /> {s.rest.split('\n').filter((l) => l.trim()).length || 0} satır</summary>
            <textarea className="rest-area" value={s.rest} spellCheck={false}
                      placeholder="option httplog&#10;timeout server 1h&#10;use_backend %[path,map_beg(/etc/haproxy/routes.map,be_default)]"
                      onChange={(e) => patch(s.id, { rest: e.target.value })} />
          </details>
        </div>
      ))}

      <div className="builder-card add-bar">
        <span>Bölüm ekle:</span>
        <button className="ghost" onClick={() => addSection('frontend')}>+ frontend</button>
        <button className="ghost" onClick={() => addSection('backend')}>+ backend</button>
        <button className="ghost" onClick={() => addSection('listen')}>+ listen</button>
        <button className="ghost" onClick={() => setSections(defaultSections())} title="Boş şablona dön">sıfırla</button>
      </div>

      <div className="builder-card">
        <div className="card-head"><h4>Önizleme</h4><small>Oluşturulan haproxy.cfg</small></div>
        <pre className="snippet">{generated}</pre>
        <div className="builder-actions">
          <button className="primary" disabled={!ready} onClick={() => onApply(generated)}>Editöre yaz</button>
          <button disabled={!ready} onClick={() => onApply(generated, true)}>Editöre yaz + Cluster’a git</button>
        </div>
      </div>
    </div>
  )
}
