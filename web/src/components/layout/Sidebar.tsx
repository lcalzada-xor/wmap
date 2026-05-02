import React from 'react';
import { Tilt } from '../common/Tilt';
import { useGraphStats } from '../../hooks/useGraphStats';

const LEGEND_ITEMS = [
  { color: 'var(--color-ap)',      label: 'Access Point' },
  { color: 'var(--color-station)', label: 'Station / Client' },
  { color: 'var(--color-network)', label: 'Network Hub' },
] as const;

interface SidebarProps {
  stats: ReturnType<typeof useGraphStats>;
  hasData: boolean;
  onClose: () => void;
}

export const Sidebar: React.FC<SidebarProps> = ({ stats, hasData, onClose }) => (
  <div className="sidebar glass-panel">
    <div className="sidebar-header">
      <h3 className="sidebar-title">Network Map</h3>
      <button className="close-btn" onClick={onClose} title="Close" aria-label="Cerrar mapa">✕</button>
    </div>

    <div className="stats-grid">
      <Tilt><div className="stat-card"><div className="stat-card-label">Access Points</div><div className="stat-card-value" style={{ color: 'var(--color-ap)' }}>{stats.apCount}</div></div></Tilt>
      <Tilt><div className="stat-card"><div className="stat-card-label">Stations</div><div className="stat-card-value" style={{ color: 'var(--color-station)' }}>{stats.stationCount}</div></div></Tilt>
      <Tilt><div className="stat-card"><div className="stat-card-label">Total Nodes</div><div className="stat-card-value">{stats.totalNodes}</div></div></Tilt>
      <Tilt><div className="stat-card"><div className="stat-card-label">Edges</div><div className="stat-card-value">{stats.edgeCount}</div></div></Tilt>
    </div>

    <Tilt>
      <div className="data-panel">
        <p className="data-panel-title">Latest Frame</p>
        <pre>{hasData ? `Nodes: ${stats.totalNodes}\nEdges: ${stats.edgeCount}\nAPs:   ${stats.apCount}\nSTAs:  ${stats.stationCount}` : 'Awaiting data...'}</pre>
      </div>
    </Tilt>

    <div className="legend-wrapper">
      <p className="legend-title">Legend</p>
      {LEGEND_ITEMS.map(({ color, label }) => (
        <div key={label} className="legend-entry">
          <div style={{ width: 10, height: 10, borderRadius: '50%', background: color, boxShadow: `0 0 6px ${color}` }} />
          <span className="legend-label">{label}</span>
        </div>
      ))}
    </div>
  </div>
);
