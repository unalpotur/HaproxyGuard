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
  section: string | null
  line_number: number | null
  suggestion: string | null
}

export interface AnalysisResult {
  findings: Finding[]
  summary: Record<string, number>
}

async function post<T>(path: string, content: string): Promise<T> {
  const res = await fetch(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ content }),
  })
  if (!res.ok) throw new Error(`${path} failed: ${res.status}`)
  return res.json()
}

export const fetchTopology = (content: string) => post<TopologyGraph>('/api/topology', content)
export const fetchAnalysis = (content: string) => post<AnalysisResult>('/api/analyze', content)
