import type { AnalysisResult } from './api'

const SEVERITY_COLOR: Record<string, string> = {
  critical: '#dc2626',
  high: '#ea580c',
  medium: '#ca8a04',
  low: '#2563eb',
  info: '#64748b',
}

export default function FindingsPanel({ result }: { result: AnalysisResult }) {
  if (result.findings.length === 0) {
    return <p className="empty">No issues found 🎉</p>
  }
  return (
    <div className="findings">
      <div className="summary">
        {Object.entries(result.summary).map(([sev, count]) => (
          <span key={sev} className="badge" style={{ background: SEVERITY_COLOR[sev] }}>
            {sev}: {count}
          </span>
        ))}
      </div>
      {result.findings.map((f, i) => (
        <div key={i} className="finding" style={{ borderLeftColor: SEVERITY_COLOR[f.severity] }}>
          <div className="finding-head">
            <span className="badge" style={{ background: SEVERITY_COLOR[f.severity] }}>
              {f.severity}
            </span>
            <strong>{f.title}</strong>
            <code>{f.rule_id}</code>
          </div>
          <p>{f.detail}</p>
          {f.suggestion && <p className="suggestion">💡 {f.suggestion}</p>}
          {f.section && (
            <small>
              section: {f.section}
              {f.line_number ? ` (line ${f.line_number})` : ''}
            </small>
          )}
        </div>
      ))}
    </div>
  )
}
