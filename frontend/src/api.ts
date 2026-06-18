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

export interface ClusterNode {
  id: string
  name: string
  address: string
  labels: Record<string, string>
  status: 'online' | 'offline' | 'pending'
  enrolled_at: string
  last_seen: string | null
  agent_version: string | null
  haproxy_version: string | null
  config_hash: string | null
  pending_version: number | null
  applied_version: number | null
  metrics: Record<string, unknown>
  deploy_status: string
  service_status: string
  last_action_result: Record<string, unknown> | null
  ssh_host: string | null
}

export interface EnrollResponse {
  node: ClusterNode
  token: string
}

export interface ClusterDeployment {
  id: string
  node_id: string
  version: number
  config_hash: string
  status: string
  created_at: string
  message: string
  findings_summary: Record<string, number>
}

export interface DeployResult {
  deployments: ClusterDeployment[]
  skipped: string[]
}

export interface DeployCheck {
  file_refs: string[]
  provided: string[]
  missing: string[]
  warnings: string[]
  findings_summary: Record<string, number>
}

export interface ClusterOverview {
  total: number
  online: number
  offline: number
  pending: number
  pending_deploys: number
  haproxy_versions: Record<string, number>
  agent_versions: Record<string, number>
  distinct_config_hashes: number
}

export interface Alert {
  severity: string
  source: string
  title: string
  detail: string
  created_at: string
}

export interface AlertChannel {
  id: string
  name: string
  type: string
  url: string
  min_severity: string
}

export interface ChannelSendResult {
  channel_id: string
  name: string
  ok: boolean
  sent: number
  message: string
}

export interface DispatchResult {
  alerts: Alert[]
  results: ChannelSendResult[]
}

export interface Principal {
  name: string
  role: 'viewer' | 'operator' | 'admin'
}

export interface AuditEntry {
  id: number
  actor: string
  role: string
  action: string
  target: string | null
  status: string
  detail: string
  created_at: string
}

export interface ConfigVersion {
  id: string
  label: string
  message: string
  author: string
  created_at: string
  content_hash: string
  size: number
  parent_id: string | null
}

export interface VersionContent {
  version: ConfigVersion
  content: string
}

function getApiKey(): string | null {
  return localStorage.getItem('hg_api_key')
}

// Auth header for GET requests to RBAC-protected endpoints (audit, whoami,
// versions, …). Without it those return 401 when HG_ADMIN_KEY is set.
function authHeaders(extra: Record<string, string> = {}): Record<string, string> {
  const key = getApiKey()
  return key ? { ...extra, 'X-API-Key': key } : { ...extra }
}

async function getJson<T>(path: string): Promise<T> {
  const res = await fetch(path, { headers: authHeaders() })
  if (!res.ok) throw new Error(`${path} failed: ${res.status}`)
  return res.json()
}

async function postJson<T>(path: string, body: unknown): Promise<T> {
  const headers: Record<string, string> = { 'Content-Type': 'application/json' }
  const key = getApiKey()
  if (key) headers['X-API-Key'] = key
  const res = await fetch(path, {
    method: 'POST',
    headers,
    body: JSON.stringify(body),
  })
  if (!res.ok) throw new Error(`${path} failed: ${res.status}`)
  return res.json()
}

const post = <T>(path: string, content: string) => postJson<T>(path, { content })

export const loadLocalConfig = async (): Promise<{ path: string; content: string }> => {
  const res = await fetch('/api/local-config')
  if (!res.ok) throw new Error(`No server config (HTTP ${res.status})`)
  return res.json()
}

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

export const clusterNodes = async (): Promise<ClusterNode[]> => {
  const res = await fetch('/api/cluster/nodes')
  if (!res.ok) throw new Error(`/api/cluster/nodes failed: ${res.status}`)
  return res.json()
}

export const clusterOverview = async (): Promise<ClusterOverview> => {
  const res = await fetch('/api/cluster/overview')
  if (!res.ok) throw new Error(`/api/cluster/overview failed: ${res.status}`)
  return res.json()
}

export const clusterEnroll = (name: string, address: string, labels: Record<string, string>,
  sshHost?: string, sshUser?: string, sshPassword?: string, autoDeploy?: boolean, manageMode?: string) =>
  postJson<EnrollResponse>('/api/cluster/nodes',
    { name, address, labels, ssh_host: sshHost, ssh_user: sshUser, ssh_password: sshPassword, auto_deploy: autoDeploy, manage_mode: manageMode })

export const clusterDeploy = (content: string, node_ids: string[], validate_config: boolean,
  files: Record<string, string> = {}) =>
  postJson<DeployResult>('/api/cluster/deploy', { content, node_ids, validate_config, files })

export const clusterDeployCheck = (content: string, provided_files: string[]) =>
  postJson<DeployCheck>('/api/cluster/deploy/check', { content, provided_files })

export const clusterRollback = (nodeId: string) =>
  postJson<ClusterDeployment>(`/api/cluster/nodes/${nodeId}/rollback`, {})

export const clusterRemove = async (nodeId: string): Promise<void> => {
  const headers: Record<string, string> = {}
  const key = getApiKey()
  if (key) headers['X-API-Key'] = key
  const res = await fetch(`/api/cluster/nodes/${nodeId}`, { method: 'DELETE', headers })
  if (!res.ok) throw new Error(`delete failed: ${res.status}`)
}

export const alertsEvaluate = (content: string, logs: string) =>
  postJson<Alert[]>('/api/alerts/evaluate', { content, logs: logs || null })

export const alertsDispatch = (content: string, logs: string) =>
  postJson<DispatchResult>('/api/alerts/dispatch', { content, logs: logs || null })

export const alertChannels = async (): Promise<AlertChannel[]> => {
  const res = await fetch('/api/alerts/channels')
  if (!res.ok) throw new Error(`/api/alerts/channels failed: ${res.status}`)
  return res.json()
}

export const addAlertChannel = (name: string, type: string, url: string, min_severity: string) =>
  postJson<AlertChannel>('/api/alerts/channels', { name, type, url, min_severity })

export const removeAlertChannel = async (id: string): Promise<void> => {
  const res = await fetch(`/api/alerts/channels/${id}`, { method: 'DELETE', headers: authHeaders() })
  if (!res.ok) throw new Error(`delete failed: ${res.status}`)
}

export const whoami = () => getJson<Principal>('/api/auth/whoami')

export const auditLog = (limit = 200) => getJson<AuditEntry[]>(`/api/audit?limit=${limit}`)

export const listVersions = () => getJson<ConfigVersion[]>('/api/versions')

export const saveVersion = (content: string, label: string, message: string) =>
  postJson<ConfigVersion>('/api/versions', { content, label, message })

export const versionDiff = (a: string, b: string) =>
  getJson<{ a: string; b: string; diff: string }>(`/api/versions/diff?a=${a}&b=${b}`)

export const restoreVersion = (id: string) =>
  postJson<VersionContent>(`/api/versions/${id}/restore`, {})

// Simulate an agent check-in from the dashboard (dev/demo aid).
export const agentHeartbeat = (nodeId: string, token: string, body: unknown) =>
  fetch(`/api/agent/${nodeId}/heartbeat`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
    body: JSON.stringify(body),
  }).then((r) => { if (!r.ok) throw new Error(`heartbeat failed: ${r.status}`); return r.json() })

export const nodeAction = (nodeId: string, actionType: string, params: Record<string, unknown> = {}) =>
  postJson<{ type: string; params: Record<string, unknown> }>(`/api/cluster/nodes/${nodeId}/action`, { type: actionType, params })

export interface NodeCert {
  path: string
  subject_cn: string
  issuer_cn: string
  not_after: string
  days_remaining: number | null
  sans: string[]
}
