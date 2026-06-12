import { useState } from 'react'
import {
  previewFixes, applyFixes, rollbackFix,
  type AnalysisResult, type FixProposal,
} from './api'

type Props = {
  config: string
  result: AnalysisResult
  onContentChange: (content: string) => void
}

export default function FixBar({ config, result, onContentChange }: Props) {
  const [proposal, setProposal] = useState<FixProposal | null>(null)
  const [version, setVersion] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const fixableCount = result.findings.filter((f) => f.fixable).length
  if (fixableCount === 0 && !version) return null

  const guard = async (fn: () => Promise<void>) => {
    setBusy(true)
    setError(null)
    try {
      await fn()
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setBusy(false)
    }
  }

  const preview = () => guard(async () => setProposal(await previewFixes(config)))

  const apply = () => guard(async () => {
    const p = await applyFixes(config)
    setProposal(p)
    if (p.changed) {
      setVersion(p.version_id)
      onContentChange(p.proposed_content)
    }
  })

  const undo = () => guard(async () => {
    if (!version) return
    const { content } = await rollbackFix(version)
    onContentChange(content)
    setVersion(null)
    setProposal(null)
  })

  return (
    <div className="fixbar">
      <div className="fixbar-actions">
        <strong>{fixableCount} auto-fixable</strong>
        <button onClick={preview} disabled={busy || fixableCount === 0}>Preview fixes</button>
        <button onClick={apply} disabled={busy || fixableCount === 0} className="primary">
          Apply &amp; rerun
        </button>
        {version && <button onClick={undo} disabled={busy} className="warn">Undo</button>}
      </div>
      {error && <p className="error">{error}</p>}
      {proposal && (
        <div className="fix-proposal">
          {proposal.changed ? (
            <>
              <ul className="applied">
                {proposal.applied.map((a, i) => (
                  <li key={i}><code>{a.rule_id}</code> {a.summary}
                    {a.section ? <em> — {a.section}</em> : null}</li>
                ))}
              </ul>
              {proposal.validation && (
                <p className={proposal.validation.ok ? 'valid-ok' : 'valid-bad'}>
                  {proposal.validation.ran
                    ? (proposal.validation.ok ? '✓ haproxy -c passed' : '✗ haproxy -c failed')
                    : 'validation skipped'}
                </p>
              )}
              <pre className="diff">{proposal.diff}</pre>
            </>
          ) : (
            <p className="empty">No automatic changes available.</p>
          )}
        </div>
      )}
    </div>
  )
}
