import React from 'react';
import { WSStatus } from '../../hooks/useWebSocket';
import { WMAPLogo } from '../icons/NetworkIcons';
import { useGraphStats } from '../../hooks/useGraphStats';

export type AppView = 'map' | 'scan';

interface TopBarProps {
  stats: ReturnType<typeof useGraphStats>;
  status: WSStatus;
  activeView: AppView;
  onViewChange: (view: AppView) => void;
}

const VIEWS: { id: AppView; label: string }[] = [
  { id: 'map',  label: 'Map'  },
  { id: 'scan', label: 'Scan' },
];

export const TopBar: React.FC<TopBarProps> = ({ stats, status, activeView, onViewChange }) => {
  const statusDotClass = status === WSStatus.OPEN ? 'connected' : status === WSStatus.ERROR ? 'error' : 'disconnected';

  return (
    <div className="top-bar glass-panel">
      <div className="top-bar-logo">
        <WMAPLogo />
        <span className="top-bar-title">WMAP</span>
      </div>

      <nav className="top-bar-tabs" aria-label="Application views">
        {VIEWS.map(v => (
          <button
            key={v.id}
            className={`top-bar-tab ${activeView === v.id ? 'active' : ''}`}
            onClick={() => onViewChange(v.id)}
            aria-current={activeView === v.id ? 'page' : undefined}
          >
            {v.label}
          </button>
        ))}
      </nav>

      <div className="top-bar-spacer" />

      <div className="top-bar-stats">
        <div className="top-bar-stat">
          <span className="top-bar-stat-value stat-ap">{stats.apCount}</span>
          <span className="top-bar-stat-label">APs</span>
        </div>
        <div className="top-bar-stat">
          <span className="top-bar-stat-value stat-sta">{stats.stationCount}</span>
          <span className="top-bar-stat-label">Stations</span>
        </div>
        {stats.networkCount > 0 && (
          <div className="top-bar-stat">
            <span className="top-bar-stat-value stat-net">{stats.networkCount}</span>
            <span className="top-bar-stat-label">Networks</span>
          </div>
        )}
      </div>

      <div className="top-bar-divider" />

      <div className="status-dot-wrapper">
        <div className={`status-dot ${statusDotClass}`} />
        <span className="status-label">{status}</span>
      </div>
    </div>
  );
};
