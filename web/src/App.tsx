import { useState } from 'react'
import { useWebSocket, WSStatus } from './hooks/useWebSocket'

function App() {
  const [isSidebarOpen, setIsSidebarOpen] = useState(true)
  
  // Note: we'll connect to /ws on port 8080 as configured via vite proxy
  // Alternatively if we're directly fetching, we can use a dynamic URL
  // Just a placeholder URL for now, the real one depends on the Go API path
  const { status, lastMessage } = useWebSocket({ url: 'ws://localhost:8080/ws' });

  return (
    <div className="app-container">
      {/* 1. Underlying Graph Layer */}
      <div className="graph-layer">
        {/* Placeholder for Canvas / WebGL Graph (e.g. react-force-graph) */}
        <div style={{ padding: '80px', color: 'rgba(255, 255, 255, 0.3)', pointerEvents: 'none' }}>
           Graph Visualization Surface...
        </div>
      </div>

      {/* 2. Floating HUD Overlay Layer */}
      <div className="hud-layer">
        
        {/* Top bar with glassmorphism */}
        <div className="top-bar glass-panel">
          <h2>WMAP Command Center</h2>
          <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: '8px' }}>
             {/* Simple Status Indicator */}
             <div style={{ 
               width: 10, 
               height: 10, 
               borderRadius: '50%', 
               backgroundColor: status === WSStatus.OPEN ? 'var(--accent-green)' : 'var(--accent-red)' 
             }} />
             <span style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>{status}</span>
          </div>
        </div>

        {/* Floating Sidebar (HUD Panel) */}
        {isSidebarOpen && (
          <div className="sidebar glass-panel">
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
              <h3>Device Stats</h3>
              <button 
                className="primary" 
                style={{ background: 'transparent', padding: '4px', border: '1px solid var(--border-glass)' }}
                onClick={() => setIsSidebarOpen(false)}
              >
                ✕
              </button>
            </div>
            
            <p>Welcome to the dashboard. The network graph is rendered continuously underneath this panel.</p>

            <div style={{ marginTop: '20px', padding: '12px', background: 'rgba(0,0,0,0.3)', borderRadius: '8px' }}>
              <h4 style={{ margin: '0 0 8px 0', color: 'var(--accent-cyan)' }}>Latest Packet</h4>
              <pre style={{ fontSize: '11px', color: 'var(--text-secondary)', overflow: 'hidden' }}>
                {lastMessage ? JSON.stringify(lastMessage, null, 2) : 'Awaiting data...'}
              </pre>
            </div>
            
            <button className="primary" style={{ width: '100%', marginTop: '20px' }}>
              Scan Network
            </button>
          </div>
        )}

        {/* Small button to reopen sidebar if closed */}
        {!isSidebarOpen && (
          <button 
            className="primary"
            style={{ position: 'absolute', top: '20px', right: '20px' }}
            onClick={() => setIsSidebarOpen(true)}
          >
            Open Menu
          </button>
        )}

      </div>
    </div>
  )
}

export default App
