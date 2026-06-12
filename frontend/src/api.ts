export interface TopologyNode {
  id: string
  type: 'frontend' | 'backend' | 'server'
  label: string
  binds?: string[]
  balance?: string | null
  address?: string
  check?: boolean
}

export interface TopologyEdge {
  source: string
  target: string
  label: string
}

export interface TopologyGraph {
  nodes: TopologyNode[]
  edges: TopologyEdge[]
}

export interface Finding {
  rule_id: string
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  title: string
  detail: string
  category: string
  section: string | null
  line_number: number | null
  suggestion: string | null
  fixable: boolean
}

export interface AnalysisResult {
  findings: Finding[]
  summary: Record<string, number>
}

export interface AppliedFix {
  rule_id: string
  summary: string
  section: string | null
}

export interface Validation {
  ran: boolean
  ok: boolean
  message: string
}

export interface FixProposal {
  original_content: string
  proposed_content: string
  diff: string
  applied: AppliedFix[]
  skipped: string[]
  changed: boolean
  validation: Validation | null
  version_id: string | null
}

export interface CertificateInfo {
  subject_cn: string
  issuer_cn: string
  serial_number: string
  not_before: string
  not_after: string
  days_remaining: number
  expiry_status: 'expired' | 'critical' | 'warning' | 'ok'
  sans: string[]
  key_type: string
  key_bits: number | null
  signature_algorithm: string
  is_self_signed: boolean
  is_ca: boolean
  issues: string[]
}

export interface CertReference {
  path: string
  kind: string
  section: string | null
  line_number: number | null
}

export interface CertEntry {
  reference: CertReference
  readable: boolean
  error: string | null
  certificates: CertificateInfo[]
}

export interface CipherAssessment {
  section: string | null
  bind: string
  min_version: string | null
  max_version: string | null
  ciphers: string | null
  ciphersuites: string | null
  alpn: string | null
  grade: 'A' | 'B' | 'C' | 'F'
  issues: string[]
}

export interface SslReport {
  references: CertReference[]
  certificates: CertEntry[]
  ciphers: CipherAssessment[]
  alerts: string[]
  summary: Record<string, number>
}

export interface SecControlSpec {
  id: string
  name: string
  category: string
  description: string
  params: Record<string, unknown>
}

export interface SecPresetSpec {
  id: string
  name: string
  description: string
  controls: { id: string; params: Record<string, unknown> }[]
}

export interface SecurityCatalog {
  controls: SecControlSpec[]
  presets: SecPresetSpec[]
}

export interface GeneratedConfig {
  preset: string | null
  controls: { id: string; name: string; category: string; params: Record<string, unknown> }[]
  global_lines: string[]
  frontend_lines: string[]
  notes: string[]
  snippet: string
}

export interface ControlStatus {
  id: string
  name: string
  category: string
  present: boolean
  sections: string[]
  detail: string
}

export interface SecurityPosture {
  controls: ControlStatus[]
  present_count: number
  total: number
  score: number
  recommendations: string[]
}

export interface RootCause {
  title: string
  severity: string
  category: string
  evidence: string
}

export interface Recommendation {
  action: string
  rationale: string
  priority: string
}

export interface LogSummary {
  total_lines: number
  parsed: number
  error_rate: number
  status_classes: Record<string, number>
  slow_count: number
  slow_threshold_ms: number
  avg_response_ms: number | null
  backends_by_error: { backend: string; errors: number; total: number }[]
}

export interface AssistantReport {
  risk_score: number
  risk_level: 'low' | 'medium' | 'high' | 'critical'
  summary: string
  root_causes: RootCause[]
  recommendations: Recommendation[]
  log_summary: LogSummary | null
  used_llm: boolean
  llm_narrative: string | null
}

async function postJson<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
  if (!res.ok) throw new Error(`${path} failed: ${res.status}`)
  return res.json()
}

const post = <T>(path: string, content: string) => postJson<T>(path, { content })

export const fetchTopology = (content: string) => post<TopologyGraph>('/api/topology', content)
export const fetchAnalysis = (content: string) => post<AnalysisResult>('/api/analyze', content)

export const previewFixes = (content: string, rule_ids?: string[]) =>
  postJson<FixProposal>('/api/fix/preview', { content, rule_ids })

export const applyFixes = (content: string, rule_ids?: string[]) =>
  postJson<FixProposal>('/api/fix/apply', { content, rule_ids })

export const rollbackFix = (version_id: string) =>
  postJson<{ version_id: string; content: string; created_at: string }>(
    '/api/fix/rollback', { version_id },
  )

export const scanSsl = (content: string, read_files = false) =>
  postJson<SslReport>('/api/ssl/scan', { content, read_files })

export const analyzeCert = (pem: string) =>
  postJson<CertificateInfo[]>('/api/ssl/analyze-cert', { pem })

export const fetchSecurityCatalog = async (): Promise<SecurityCatalog> => {
  const res = await fetch('/api/security/catalog')
  if (!res.ok) throw new Error(`/api/security/catalog failed: ${res.status}`)
  return res.json()
}

export const generateSecurity = (preset: string) =>
  postJson<GeneratedConfig>('/api/security/generate', { preset })

export const securityPosture = (content: string) =>
  postJson<SecurityPosture>('/api/security/posture', { content })

export const assistantStatus = async (): Promise<{ llm_available: boolean }> => {
  const res = await fetch('/api/assistant/status')
  if (!res.ok) throw new Error(`/api/assistant/status failed: ${res.status}`)
  return res.json()
}

export const assistantAnalyze = (content: string, logs: string, use_llm: boolean) =>
  postJson<AssistantReport>('/api/assistant/analyze', {
    content, logs: logs || null, use_llm,
  })
