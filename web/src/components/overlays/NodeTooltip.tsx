import React from 'react';
import type { GraphNode } from '../../types/graph';
import { getRSSILabel, getTypeColor } from '../../utils/nodeUtils';
import { AccessPointIcon, StationIcon, NetworkIcon } from '../icons/NetworkIcons';
import './NodeTooltip.css';

interface NodeTooltipProps {
  node: GraphNode | null;
  posX: number | null;
  posY: number | null;
}

const SignalBars: React.FC<{ bars: number; color: string }> = ({ bars, color }) => (
  <div className="signal-bars">
    {[1, 2, 3, 4, 5].map(i => (
      <div
        key={i}
        className="signal-bar"
        style={{ height: `${i * 2.5 + 2}px`, background: i <= bars ? color : undefined }}
      />
    ))}
  </div>
);

const Badge: React.FC<{ label: string; color: string }> = ({ label, color }) => (
  <span className="badge" style={{ borderColor: `${color}55`, color, background: `${color}18` }}>
    {label}
  </span>
);

export const NodeTooltip: React.FC<NodeTooltipProps> = React.memo(({ node, posX, posY }) => {
  if (!node || posX === null || posY === null) return null;

  const rssiInfo  = getRSSILabel(node.rssi);
  const typeColor = getTypeColor(node.group);

  const tooltipWidth  = 240;
  const tooltipHeight = 220;
  const isNearRight  = posX > window.innerWidth  - tooltipWidth  - 40;
  const isNearBottom = posY > window.innerHeight - tooltipHeight;
  const tx = isNearRight  ? 'calc(-100% - 18px)' : '18px';
  const ty = isNearBottom ? 'calc(-100% - 18px)' : '18px';

  const containerStyle = {
    '--type-color':          typeColor,
    '--type-color-alpha':    `${typeColor}44`,
    '--type-color-alpha-bg': `${typeColor}18`,
    '--type-color-alpha-low':`${typeColor}22`,
    '--tx': tx,
    '--ty': ty,
    left: posX,
    top:  posY,
    transform: `translate3d(${tx}, ${ty}, 0)`,
  } as React.CSSProperties;

  const renderIcon = () => {
    switch (node.group) {
      case 'ap':      return <AccessPointIcon color={typeColor} size={18} />;
      case 'station': return <StationIcon     color={typeColor} size={18} />;
      case 'network': return <NetworkIcon     color={typeColor} size={18} />;
      default:        return null;
    }
  };

  const hasCapBadges = node.is_wifi6 || node.is_wifi7 || node.has_handshake || node.is_randomized || node.wps_info;

  return (
    <div className="node-tooltip" style={containerStyle} role="tooltip" aria-live="polite">
      <div className="tooltip-accent-bar" />

      {/* Header */}
      <div className="tooltip-header">
        <div className="tooltip-icon-wrapper">{renderIcon()}</div>
        <div className="tooltip-title-container">
          <div className="tooltip-title">{node.ssid || node.label || node.mac || node.id}</div>
          <div className="tooltip-subtitle">
            {node.group === 'ap' ? 'Access Point' : node.group === 'station' ? 'Client Device' : 'Network Hub'}
          </div>
        </div>
      </div>

      <div className="tooltip-body">
        {/* MAC */}
        {node.mac && (
          <div className="tooltip-stat-item">
            <span className="tooltip-stat-label">MAC</span>
            <span className="tooltip-stat-value monospace">{node.mac}</span>
          </div>
        )}

        {/* RSSI */}
        {node.rssi !== undefined && (
          <div className="tooltip-signal-panel">
            <div className="tooltip-signal-info">
              <div className="tooltip-signal-label">Signal</div>
              <div className="tooltip-signal-value" style={{ color: rssiInfo.color }}>{node.rssi} dBm</div>
            </div>
            <div className="tooltip-signal-side">
              <SignalBars bars={rssiInfo.bars} color={rssiInfo.color} />
              <span className="signal-status-text" style={{ color: rssiInfo.color }}>{rssiInfo.label}</span>
            </div>
          </div>
        )}

        {/* Channel + Security */}
        {(node.channel || node.security) && (
          <div className="tooltip-info-grid">
            {node.channel && (
              <div className="tooltip-info-box">
                <div className="tooltip-info-label">Channel</div>
                <div className="tooltip-info-value">{node.channel}</div>
              </div>
            )}
            {node.security && (
              <div className="tooltip-info-box">
                <div className="tooltip-info-label">Security</div>
                <div className="tooltip-info-value small" style={{ color: '#f59e0b' }}>{node.security}</div>
              </div>
            )}
          </div>
        )}

        {/* Key badges only */}
        {hasCapBadges && (
          <div className="tooltip-badge-container">
            {node.is_wifi7 && <Badge label="WiFi 7" color="#06b6d4" />}
            {node.is_wifi6 && !node.is_wifi7 && <Badge label="WiFi 6" color="#06b6d4" />}
            {node.has_handshake && <Badge label="Handshake" color="#10b981" />}
            {node.is_randomized && <Badge label="Random MAC" color="#f59e0b" />}
            {node.wps_info && <Badge label="WPS" color="#8b5cf6" />}
          </div>
        )}

        <div className="tooltip-hint">Click for full details →</div>
      </div>
    </div>
  );
});

NodeTooltip.displayName = 'NodeTooltip';
