import React from 'react';
import type { GraphNode } from '../../types/graph';

interface NodeTooltipProps {
  node: GraphNode | null;
}

// ─── Helpers ────────────────────────────────────────────────────────────────

function getRSSILabel(rssi?: number): { label: string; color: string; bars: number } {
  if (rssi === undefined) return { label: 'N/A', color: '#7d92b0', bars: 0 };
  if (rssi >= -55) return { label: 'Excellent', color: '#10b981', bars: 5 };
  if (rssi >= -65) return { label: 'Good',      color: '#10b981', bars: 4 };
  if (rssi >= -75) return { label: 'Fair',       color: '#f59e0b', bars: 3 };
  if (rssi >= -85) return { label: 'Poor',       color: '#ef4444', bars: 2 };
  return              { label: 'Weak',       color: '#ef4444', bars: 1 };
}

function getNodeTypeIcon(group: string): React.ReactNode {
  switch (group) {
    case 'ap':
      return (
        <svg width="20" height="20" viewBox="0 0 64 64" fill="none" xmlns="http://www.w3.org/2000/svg">
          <path d="M14 28C18.2 21.4 24.7 17 32 17C39.3 17 45.8 21.4 50 28" stroke="#06b6d4" strokeWidth="3.5" strokeLinecap="round"/>
          <path d="M20 33C22.9 28.3 27.1 25 32 25C36.9 25 41.1 28.3 44 33" stroke="#06b6d4" strokeWidth="3.5" strokeLinecap="round"/>
          <path d="M26 38C27.7 35.2 29.7 33.5 32 33.5C34.3 33.5 36.3 35.2 38 38" stroke="#06b6d4" strokeWidth="3.5" strokeLinecap="round"/>
          <circle cx="32" cy="43" r="3.5" fill="#06b6d4"/>
          <line x1="32" y1="43" x2="32" y2="48" stroke="#06b6d4" strokeWidth="3" strokeLinecap="round"/>
          <rect x="20" y="48" width="24" height="4" rx="2" fill="#06b6d4" fillOpacity="0.8"/>
        </svg>
      );
    case 'station':
      return (
        <svg width="20" height="20" viewBox="0 0 64 64" fill="none" xmlns="http://www.w3.org/2000/svg">
          <rect x="13" y="14" width="38" height="26" rx="3" stroke="#8b5cf6" strokeWidth="2.5"/>
          <line x1="19" y1="22" x2="37" y2="22" stroke="#8b5cf6" strokeWidth="1.5" strokeLinecap="round" opacity="0.7"/>
          <line x1="19" y1="27" x2="33" y2="27" stroke="#8b5cf6" strokeWidth="1.5" strokeLinecap="round" opacity="0.7"/>
          <line x1="13" y1="40" x2="51" y2="40" stroke="#8b5cf6" strokeWidth="2.5" strokeLinecap="round"/>
          <path d="M8 40 L11 47 H53 L56 40" stroke="#8b5cf6" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"/>
        </svg>
      );
    case 'network':
      return (
        <svg width="20" height="20" viewBox="0 0 64 64" fill="none" xmlns="http://www.w3.org/2000/svg">
          <polygon points="32,8 54,20 54,44 32,56 10,44 10,20" stroke="#10b981" strokeWidth="2.5" strokeLinejoin="round"/>
          <circle cx="32" cy="32" r="5" fill="#10b981"/>
          <line x1="32" y1="27" x2="32" y2="11" stroke="#10b981" strokeWidth="1.5" opacity="0.7"/>
          <line x1="36.3" y1="29.5" x2="51" y2="21" stroke="#10b981" strokeWidth="1.5" opacity="0.7"/>
          <line x1="36.3" y1="34.5" x2="51" y2="43" stroke="#10b981" strokeWidth="1.5" opacity="0.7"/>
          <line x1="32" y1="37" x2="32" y2="53" stroke="#10b981" strokeWidth="1.5" opacity="0.7"/>
          <line x1="27.7" y1="34.5" x2="13" y2="43" stroke="#10b981" strokeWidth="1.5" opacity="0.7"/>
          <line x1="27.7" y1="29.5" x2="13" y2="21" stroke="#10b981" strokeWidth="1.5" opacity="0.7"/>
        </svg>
      );
    default:
      return null;
  }
}

function getTypeColor(group: string): string {
  switch (group) {
    case 'ap':      return '#06b6d4';
    case 'station': return '#8b5cf6';
    case 'network': return '#10b981';
    default:        return '#7d92b0';
  }
}

// ─── Signal Bars Component ──────────────────────────────────────────────────

const SignalBars: React.FC<{ bars: number; color: string }> = ({ bars, color }) => (
  <div style={{ display: 'flex', alignItems: 'flex-end', gap: '2px', height: '14px' }}>
    {[1, 2, 3, 4, 5].map(i => (
      <div
        key={i}
        style={{
          width: '4px',
          height: `${i * 2.5 + 2}px`,
          borderRadius: '1px',
          background: i <= bars ? color : 'rgba(255,255,255,0.1)',
          transition: 'background 0.3s ease',
        }}
      />
    ))}
  </div>
);

// ─── Badge Component ─────────────────────────────────────────────────────────

const Badge: React.FC<{ label: string; color: string }> = ({ label, color }) => (
  <span style={{
    fontSize: '9px',
    fontWeight: 700,
    letterSpacing: '0.08em',
    textTransform: 'uppercase',
    padding: '2px 6px',
    borderRadius: '4px',
    border: `1px solid ${color}55`,
    color: color,
    background: `${color}18`,
  }}>
    {label}
  </span>
);

// ─── Main Component ──────────────────────────────────────────────────────────

export const NodeTooltip: React.FC<NodeTooltipProps> = ({ node }) => {
  if (!node) return null;

  const rssiInfo = getRSSILabel(node.rssi);
  const typeColor = getTypeColor(node.group);

  return (
    <div
      style={{
        position: 'absolute',
        top: 18,
        left: 18,
        width: '260px',
        background: 'rgba(6, 10, 22, 0.80)',
        backdropFilter: 'blur(20px)',
        WebkitBackdropFilter: 'blur(20px)',
        border: `1px solid ${typeColor}44`,
        borderRadius: '14px',
        color: 'white',
        pointerEvents: 'none',
        zIndex: 20,
        overflow: 'hidden',
        boxShadow: `0 8px 40px rgba(0,0,0,0.6), 0 0 0 1px ${typeColor}22, inset 0 1px 0 rgba(255,255,255,0.06)`,
        animation: 'tooltipFadeIn 0.18s ease-out',
      }}
    >
      {/* Top accent bar */}
      <div style={{
        height: '2px',
        background: `linear-gradient(90deg, transparent, ${typeColor}, transparent)`,
      }} />

      {/* Header */}
      <div style={{
        padding: '12px 14px 10px',
        display: 'flex',
        alignItems: 'center',
        gap: '10px',
        borderBottom: `1px solid rgba(255,255,255,0.06)`,
      }}>
        <div style={{
          width: 36, height: 36,
          borderRadius: 10,
          background: `${typeColor}18`,
          border: `1px solid ${typeColor}44`,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          flexShrink: 0,
        }}>
          {getNodeTypeIcon(node.group)}
        </div>
        <div style={{ overflow: 'hidden' }}>
          <div style={{
            fontSize: '13px',
            fontWeight: 700,
            color: 'white',
            whiteSpace: 'nowrap',
            overflow: 'hidden',
            textOverflow: 'ellipsis',
          }}>
            {node.ssid || node.label || node.mac || node.id}
          </div>
          <div style={{
            fontSize: '10px',
            color: typeColor,
            fontWeight: 600,
            letterSpacing: '0.1em',
            textTransform: 'uppercase',
            marginTop: '1px',
          }}>
            {node.group === 'ap' ? 'Access Point' : node.group === 'station' ? 'Client Device' : 'Network Hub'}
          </div>
        </div>
      </div>

      {/* Body */}
      <div style={{ padding: '10px 14px', display: 'flex', flexDirection: 'column', gap: '8px' }}>

        {/* MAC & Vendor */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
          {node.mac && (
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontSize: '10px', color: '#5a7090', fontWeight: 500 }}>MAC</span>
              <span style={{ fontSize: '11px', color: '#a0b4cc', fontFamily: 'monospace', letterSpacing: '0.05em' }}>
                {node.mac}
              </span>
            </div>
          )}
          {node.vendor && (
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontSize: '10px', color: '#5a7090', fontWeight: 500 }}>Vendor</span>
              <span style={{ fontSize: '11px', color: '#a0b4cc' }}>{node.vendor}</span>
            </div>
          )}
        </div>

        {/* RSSI Signal Bar */}
        {node.rssi !== undefined && (
          <div style={{
            background: 'rgba(0,0,0,0.2)',
            borderRadius: '8px',
            padding: '8px 10px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            gap: '8px',
          }}>
            <div>
              <div style={{ fontSize: '9px', color: '#5a7090', fontWeight: 600, letterSpacing: '0.1em', textTransform: 'uppercase', marginBottom: '3px' }}>Signal</div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                <span style={{ fontSize: '15px', fontWeight: 700, color: rssiInfo.color, fontFamily: 'monospace' }}>
                  {node.rssi} dBm
                </span>
              </div>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: '4px' }}>
              <SignalBars bars={rssiInfo.bars} color={rssiInfo.color} />
              <span style={{ fontSize: '9px', fontWeight: 700, color: rssiInfo.color, letterSpacing: '0.08em', textTransform: 'uppercase' }}>
                {rssiInfo.label}
              </span>
            </div>
          </div>
        )}

        {/* Radio Info */}
        {(node.channel || node.frequency || node.bw || node.standard) && (
          <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap' }}>
            {node.channel && (
              <div style={{ flex: 1, minWidth: '60px', background: 'rgba(0,0,0,0.2)', borderRadius: '6px', padding: '5px 8px' }}>
                <div style={{ fontSize: '8px', color: '#5a7090', textTransform: 'uppercase', letterSpacing: '0.1em' }}>Channel</div>
                <div style={{ fontSize: '13px', fontWeight: 700, color: 'white' }}>{node.channel}</div>
              </div>
            )}
            {node.bw && (
              <div style={{ flex: 1, minWidth: '60px', background: 'rgba(0,0,0,0.2)', borderRadius: '6px', padding: '5px 8px' }}>
                <div style={{ fontSize: '8px', color: '#5a7090', textTransform: 'uppercase', letterSpacing: '0.1em' }}>Width</div>
                <div style={{ fontSize: '13px', fontWeight: 700, color: 'white' }}>{node.bw}MHz</div>
              </div>
            )}
            {node.security && (
              <div style={{ flex: 1, minWidth: '60px', background: 'rgba(0,0,0,0.2)', borderRadius: '6px', padding: '5px 8px' }}>
                <div style={{ fontSize: '8px', color: '#5a7090', textTransform: 'uppercase', letterSpacing: '0.1em' }}>Security</div>
                <div style={{ fontSize: '11px', fontWeight: 700, color: '#f59e0b' }}>{node.security}</div>
              </div>
            )}
          </div>
        )}

        {/* Capability Badges */}
        {(node.is_wifi6 || node.is_wifi7 || node.has_handshake || node.is_randomized || node.wps_info) && (
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '4px' }}>
            {node.is_wifi7 && <Badge label="WiFi 7" color="#06b6d4" />}
            {node.is_wifi6 && !node.is_wifi7 && <Badge label="WiFi 6" color="#06b6d4" />}
            {node.has_handshake && <Badge label="🔑 Handshake" color="#10b981" />}
            {node.is_randomized && <Badge label="Random MAC" color="#f59e0b" />}
            {node.wps_info && <Badge label="WPS" color="#8b5cf6" />}
          </div>
        )}

        {/* Traffic Stats */}
        {(node.packets > 0) && (
          <div style={{ display: 'flex', justifyContent: 'space-between', padding: '6px 0', borderTop: '1px solid rgba(255,255,255,0.05)' }}>
            <div style={{ textAlign: 'center' }}>
              <div style={{ fontSize: '9px', color: '#5a7090', textTransform: 'uppercase', letterSpacing: '0.1em' }}>Packets</div>
              <div style={{ fontSize: '13px', fontWeight: 700, color: 'white' }}>{node.packets?.toLocaleString()}</div>
            </div>
            <div style={{ textAlign: 'center' }}>
              <div style={{ fontSize: '9px', color: '#5a7090', textTransform: 'uppercase', letterSpacing: '0.1em' }}>Retries</div>
              <div style={{ fontSize: '13px', fontWeight: 700, color: node.retries > 50 ? '#ef4444' : 'white' }}>{node.retries}</div>
            </div>
            <div style={{ textAlign: 'center' }}>
              <div style={{ fontSize: '9px', color: '#5a7090', textTransform: 'uppercase', letterSpacing: '0.1em' }}>TX</div>
              <div style={{ fontSize: '13px', fontWeight: 700, color: 'white' }}>{node.data_tx?.toLocaleString()}</div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
