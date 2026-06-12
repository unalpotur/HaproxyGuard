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
