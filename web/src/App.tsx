import { useState, useMemo, useRef } from 'react'
import { useWebSocket, WSStatus } from './hooks/useWebSocket'
import { DeviceGraph } from './components/graph/DeviceGraph'
import type { GraphData, WSGraphMessage } from './types/graph'

// ─── Network icon for top bar ────────────────────────────────────────────────
const NetworkIcon = () => (
  <svg width="28" height="28" viewBox="0 0 64 64" fill="none" xmlns="http://www.w3.org/2000/svg">
    <path d="M14 28C18.2 21.4 24.7 17 32 17C39.3 17 45.8 21.4 50 28" stroke="#06b6d4" strokeWidth="3.5" strokeLinecap="round"/>
    <path d="M20 33C22.9 28.3 27.1 25 32 25C36.9 25 41.1 28.3 44 33" stroke="#06b6d4" strokeWidth="3.5" strokeLinecap="round"/>
    <path d="M26 38C27.7 35.2 29.7 33.5 32 33.5C34.3 33.5 36.3 35.2 38 38" stroke="#06b6d4" strokeWidth="3.5" strokeLinecap="round"/>
    <circle cx="32" cy="43" r="3.5" fill="#06b6d4"/>
  </svg>
)

const WS_OPTIONS = { url: 'ws://localhost:8080/ws' };

function App() {
  const [isSidebarOpen, setIsSidebarOpen] = useState(true)

  const { status, lastMessage } = useWebSocket(WS_OPTIONS)

  // Persist the last valid graph payload so nodes are NOT wiped on WS disconnect/reconnect
  const lastValidGraphDataRef = useRef<GraphData | null>(null)

  const graphData = useMemo<GraphData | null>(() => {
    if (lastMessage && lastMessage.type === 'graph') {
      lastValidGraphDataRef.current = (lastMessage as WSGraphMessage).payload
      return lastValidGraphDataRef.current
    }
    // Return the last known valid snapshot while WS is reconnecting
    return lastValidGraphDataRef.current
  }, [lastMessage])

  // Derive live counts from graph data
  const apCount      = graphData?.nodes.filter(n => n.group === 'ap').length      ?? 0
  const stationCount = graphData?.nodes.filter(n => n.group === 'station').length ?? 0
  const networkCount = graphData?.nodes.filter(n => n.group === 'network').length ?? 0

  const isConnected = status === WSStatus.OPEN

  return (
    <div className="app-container">

      {/* 1. Underlying Graph Layer */}
      <div className="graph-layer">
        <DeviceGraph graphData={graphData} />
      </div>

      {/* 2. Floating HUD Overlay Layer */}
      <div className="hud-layer">

        {/* ── Top Bar ──────────────────────────────────────── */}
        <div className="top-bar glass-panel">
          <div className="top-bar-logo">
            <NetworkIcon />
            <span className="top-bar-title">WMAP</span>
          </div>

          <div className="top-bar-divider" />

          <div className="top-bar-stats">
            <div className="top-bar-stat">
              <span className="top-bar-stat-value stat-ap">{apCount}</span>
              <span className="top-bar-stat-label">APs</span>
            </div>
            <div className="top-bar-stat">
              <span className="top-bar-stat-value stat-sta">{stationCount}</span>
              <span className="top-bar-stat-label">Stations</span>
            </div>
            {networkCount > 0 && (
              <div className="top-bar-stat">
                <span className="top-bar-stat-value stat-net">{networkCount}</span>
                <span className="top-bar-stat-label">Networks</span>
              </div>
            )}
          </div>

          <div className="top-bar-divider" />

          <div className="status-dot-wrapper">
            <div className={`status-dot ${isConnected ? 'connected' : 'disconnected'}`} />
            <span className="status-label">{status}</span>
          </div>
        </div>

        {/* ── Sidebar ──────────────────────────────────────── */}
        {isSidebarOpen && (
          <div className="sidebar glass-panel">
            <div className="sidebar-header">
              <h3 className="sidebar-title">Network Map</h3>
              <button className="close-btn" onClick={() => setIsSidebarOpen(false)} title="Close">✕</button>
            </div>

            {/* Node type stats */}
            <div className="stats-grid">
              <div className="stat-card">
                <div className="stat-card-label">Access Points</div>
                <div className="stat-card-value" style={{ color: 'var(--color-ap)' }}>{apCount}</div>
              </div>
              <div className="stat-card">
                <div className="stat-card-label">Stations</div>
                <div className="stat-card-value" style={{ color: 'var(--color-station)' }}>{stationCount}</div>
              </div>
              <div className="stat-card">
                <div className="stat-card-label">Total Nodes</div>
                <div className="stat-card-value">{apCount + stationCount + networkCount}</div>
              </div>
              <div className="stat-card">
                <div className="stat-card-label">Edges</div>
                <div className="stat-card-value">{graphData?.edges.length ?? 0}</div>
              </div>
            </div>

            {/* Live data panel */}
            <div className="data-panel">
              <p className="data-panel-title">Latest Frame</p>
              <pre>
                {graphData
                  ? `Nodes: ${graphData.nodes.length}\nEdges: ${graphData.edges.length}\nAPs:   ${apCount}\nSTAs:  ${stationCount}`
                  : 'Awaiting data...'}
              </pre>
            </div>

            {/* Legend */}
            <div style={{ marginTop: '12px', padding: '12px', background: 'rgba(0,0,0,0.2)', borderRadius: '10px', display: 'flex', flexDirection: 'column', gap: '8px' }}>
              <p style={{ margin: 0, fontSize: '9px', fontWeight: 700, letterSpacing: '0.12em', textTransform: 'uppercase', color: 'var(--text-muted)' }}>Legend</p>
              {[
                { color: 'var(--color-ap)',      label: 'Access Point' },
                { color: 'var(--color-station)', label: 'Station / Client' },
                { color: 'var(--color-network)', label: 'Network Hub' },
              ].map(({ color, label }) => (
                <div key={label} style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <div style={{ width: 10, height: 10, borderRadius: '50%', background: color, boxShadow: `0 0 6px ${color}` }} />
                  <span style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>{label}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Open sidebar button */}
        {!isSidebarOpen && (
          <button className="open-sidebar-btn" onClick={() => setIsSidebarOpen(true)}>
            ☰ Map
          </button>
        )}

      </div>
    </div>
  )
}

export default App
