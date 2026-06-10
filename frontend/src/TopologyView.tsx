import { useMemo } from 'react'
import { ReactFlow, Background, Controls, type Node, type Edge, MarkerType, Position } from '@xyflow/react'
import '@xyflow/react/dist/style.css'
import type { TopologyGraph } from './api'

const COLUMN_X: Record<string, number> = { frontend: 0, backend: 320, server: 640 }
const NODE_STYLE: Record<string, React.CSSProperties> = {
  frontend: { background: '#1d4ed8', color: 'white', border: 'none' },
  backend: { background: '#047857', color: 'white', border: 'none' },
  server: { background: '#334155', color: 'white', border: 'none' },
}

function layout(graph: TopologyGraph): { nodes: Node[]; edges: Edge[] } {
  const counters: Record<string, number> = { frontend: 0, backend: 0, server: 0 }
  const nodes: Node[] = graph.nodes.map((n) => {
    const row = counters[n.type]++
    const sub =
      n.type === 'frontend' ? (n.binds ?? []).join(', ')
      : n.type === 'backend' ? (n.balance ? `balance: ${n.balance}` : '')
      : `${n.address ?? ''}${n.check ? ' ✓check' : ''}`
    return {
      id: n.id,
      position: { x: COLUMN_X[n.type], y: row * 90 + (n.type === 'server' ? 0 : 40) },
      data: {
        label: (
          <div>
            <strong>{n.label}</strong>
            {sub && <div style={{ fontSize: 11, opacity: 0.8 }}>{sub}</div>}
          </div>
        ),
      },
      style: { ...NODE_STYLE[n.type], borderRadius: 8, padding: 8, width: 220 },
      sourcePosition: Position.Right,
      targetPosition: Position.Left,
    }
  })
  const edges: Edge[] = graph.edges.map((e, i) => ({
    id: `e${i}`,
    source: e.source,
    target: e.target,
    label: e.label || undefined,
    animated: e.label === 'default',
    markerEnd: { type: MarkerType.ArrowClosed },
  }))
  return { nodes, edges }
}

export default function TopologyView({ graph }: { graph: TopologyGraph }) {
  const { nodes, edges } = useMemo(() => layout(graph), [graph])
  return (
    <div style={{ height: '100%' }}>
      <ReactFlow nodes={nodes} edges={edges} fitView colorMode="dark">
        <Background />
        <Controls />
      </ReactFlow>
    </div>
  )
}
