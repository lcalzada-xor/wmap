import React, { useState } from 'react';
import type { GraphNode } from '../../types/graph';
import { getRSSILabel, getTypeColor, getGroupLabel, formatBytes } from '../../utils/nodeUtils';
import { AccessPointIcon, StationIcon, NetworkIcon } from '../icons/NetworkIcons';

interface RightPanelProps {
  node: GraphNode | null;
  onClose: () => void;
}

const SignalBars: React.FC<{ bars: number; color: string }> = ({ bars, color }) => (
  <div className="ndp-signal-bars">
    {[1, 2, 3, 4, 5].map(i => (
      <div
        key={i}
        className="ndp-signal-bar"
        style={{ height: `${i * 3 + 4}px`, background: i <= bars ? color : undefined }}
      />
    ))}
  </div>
);

const Badge: React.FC<{ label: string; color: string }> = ({ label, color }) => (
  <span className="ndp-badge" style={{ borderColor: `${color}55`, color, background: `${color}18` }}>
    {label}
  </span>
);

const Section: React.FC<{ title: string; children: React.ReactNode }> = ({ title, children }) => (
  <div className="ndp-section">
    <div className="ndp-section-title">{title}</div>
    {children}
  </div>
);

const CollapsibleSection: React.FC<{ title: string; children: React.ReactNode; defaultOpen?: boolean }> = ({ title, children, defaultOpen = false }) => {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div className="ndp-section">
      <button className="ndp-section-toggle" onClick={() => setOpen(o => !o)}>
        <span className="ndp-section-title">{title}</span>
        <span className="ndp-section-chevron" style={{ transform: open ? 'rotate(90deg)' : 'rotate(0deg)' }}>›</span>
      </button>
      {open && children}
    </div>
  );
};

const Row: React.FC<{ label: string; value: React.ReactNode; mono?: boolean }> = ({ label, value, mono }) => (
  <div className="ndp-row">
    <span className="ndp-row-label">{label}</span>
    <span className={`ndp-row-value ${mono ? 'mono' : ''}`}>{value}</span>
  </div>
);

// Lista de SSIDs con expand/collapse integrado en el panel
const SSIDList: React.FC<{ ssids: string[] }> = ({ ssids }) => {
  const [expanded, setExpanded] = useState(false);
  const PREVIEW = 4;
  const shown = expanded ? ssids : ssids.slice(0, PREVIEW);
  const remaining = ssids.length - PREVIEW;

  return (
    <div className="ndp-probe-list">
      {shown.map((s, i) => (
        <span key={i} className="ndp-probe-item">{s || '<hidden>'}</span>
      ))}
      {!expanded && remaining > 0 && (
        <button className="ndp-show-more" onClick={() => setExpanded(true)}>
          +{remaining} more
        </button>
      )}
      {expanded && ssids.length > PREVIEW && (
        <button className="ndp-show-more" onClick={() => setExpanded(false)}>
          Show less
        </button>
      )}
    </div>
  );
};

function bssUtilPercent(raw: number): number {
  return Math.round((raw / 255) * 100);
}

export const RightPanel: React.FC<RightPanelProps> = ({ node, onClose }) => {
  const isOpen = node !== null;

  const renderIcon = (n: GraphNode) => {
    const color = getTypeColor(n.group);
    switch (n.group) {
      case 'ap':      return <AccessPointIcon color={color} size={22} />;
      case 'station': return <StationIcon color={color} size={22} />;
      case 'network': return <NetworkIcon color={color} size={22} />;
    }
  };

  return (
    <div className={`node-detail-panel glass-panel ${isOpen ? 'open' : ''}`}>
      {node && (
        <>
          {/* Header */}
          <div className="ndp-header" style={{ '--type-color': getTypeColor(node.group) } as React.CSSProperties}>
            <div className="ndp-header-icon">{renderIcon(node)}</div>
            <div className="ndp-header-info">
              <div className="ndp-header-name">{node.ssid || node.label || node.mac || node.id}</div>
              <div className="ndp-header-type" style={{ color: getTypeColor(node.group) }}>
                {getGroupLabel(node.group)}
              </div>
            </div>
            <button className="ndp-close-btn" onClick={onClose} aria-label="Close detail panel">✕</button>
          </div>

          <div className="ndp-body">

            {/* Signal */}
            {node.rssi !== undefined && (() => {
              const rssi = getRSSILabel(node.rssi);
              return (
                <Section title="Signal">
                  <div className="ndp-signal-row">
                    <div className="ndp-signal-main">
                      <span className="ndp-signal-dbm" style={{ color: rssi.color }}>{node.rssi} dBm</span>
                      <span className="ndp-signal-quality" style={{ color: rssi.color }}>{rssi.label}</span>
                    </div>
                    <SignalBars bars={rssi.bars} color={rssi.color} />
                  </div>
                </Section>
              );
            })()}

            {/* Identity */}
            <Section title="Identity">
              {node.mac    && <Row label="MAC"    value={node.mac}    mono />}
              {node.vendor && <Row label="Vendor" value={node.vendor} />}
              {node.model  && <Row label="Model"  value={node.model}  />}
              {node.os     && <Row label="OS"     value={node.os}     />}
            </Section>

            {/* Radio */}
            {(node.ssid || node.channel || node.frequency || node.bw || node.security || node.standard || node.crypto) && (
              <Section title="Radio">
                {node.ssid      && <Row label="SSID"      value={node.ssid} />}
                {node.channel   && <Row label="Channel"   value={node.channel} />}
                {node.frequency && (
                  <Row label="Frequency" value={
                    node.frequency >= 1000
                      ? `${(node.frequency / 1000).toFixed(3)} GHz`
                      : `${node.frequency} MHz`
                  } />
                )}
                {node.bw        && <Row label="Width"     value={`${node.bw} MHz`} />}
                {node.security  && (
                  <Row label="Security" value={
                    <span style={{ color: node.security === 'OPN' ? '#ef4444' : '#f59e0b' }}>{node.security}</span>
                  } />
                )}
                {node.crypto    && (
                  <Row label="Cipher" value={
                    <span style={{ color: '#a78bfa' }}>{node.crypto}</span>
                  } />
                )}
                {node.standard  && <Row label="Standard"  value={node.standard} />}
              </Section>
            )}

            {/* BSS Load — AP only */}
            {node.group === 'ap' && node.bss_load && (
              <Section title="BSS Load">
                <div className="ndp-bssload">
                  <div className="ndp-bssload-header">
                    <span className="ndp-row-label">Channel utilization</span>
                    <span className="ndp-row-value">{bssUtilPercent(node.bss_load.channel_utilization)}%</span>
                  </div>
                  <div className="ndp-bssload-track">
                    <div
                      className="ndp-bssload-fill"
                      style={{ width: `${bssUtilPercent(node.bss_load.channel_utilization)}%` }}
                    />
                  </div>
                </div>
                <Row label="Stations" value={node.bss_load.station_count} />
                <Row label="Avail. admission" value={node.bss_load.available_admission} />
              </Section>
            )}

            {/* Capabilities */}
            {(node.is_wifi6 || node.is_wifi7 || node.has_handshake || node.is_randomized || node.wps_info || node.has11k || node.has11v || node.has11r) && (
              <Section title="Capabilities">
                <div className="ndp-badges">
                  {node.is_wifi7 && <Badge label="WiFi 7" color="#06b6d4" />}
                  {node.is_wifi6 && !node.is_wifi7 && <Badge label="WiFi 6" color="#06b6d4" />}
                  {node.has_handshake && <Badge label="Handshake" color="#10b981" />}
                  {node.is_randomized && <Badge label="Random MAC" color="#f59e0b" />}
                  {node.wps_info && <Badge label={`WPS · ${node.wps_info}`} color="#8b5cf6" />}
                  {node.has11k && <Badge label="802.11k" color="#475569" />}
                  {node.has11v && <Badge label="802.11v" color="#475569" />}
                  {node.has11r && <Badge label="802.11r" color="#475569" />}
                </div>
              </Section>
            )}

            {/* Handshake file — AP only */}
            {node.group === 'ap' && node.has_handshake && (
              <Section title="Handshake">
                {node.handshake_file ? (
                  <>
                    <div className="ndp-hs-row">
                      <span className="ndp-hs-path" title={node.handshake_file}>
                        {node.handshake_file.split('/').pop()}
                      </span>
                      <button
                        className="ndp-hs-copy"
                        title="Copy full path"
                        onClick={() => navigator.clipboard.writeText(node.handshake_file!)}
                      >
                        copy
                      </button>
                    </div>
                    <div className="ndp-hs-full">{node.handshake_file}</div>
                  </>
                ) : (
                  <span className="ndp-hs-full">Captured — path unavailable</span>
                )}
              </Section>
            )}

            {/* Connection — Station only */}
            {node.group === 'station' && node.connection_state && (
              <Section title="Connection">
                <Row label="State" value={
                  <span style={{
                    color: node.connection_state === 'connected' ? '#10b981'
                         : node.connection_state === 'disconnected' ? '#6b7280'
                         : '#f59e0b',
                    fontWeight: 600,
                  }}>
                    {node.connection_state}
                  </span>
                } />
                {node.connection_target && <Row label="AP (BSSID)" value={node.connection_target} mono />}
                {node.connection_error  && (
                  <Row label="Error" value={
                    <span style={{ color: '#ef4444' }}>{node.connection_error}</span>
                  } />
                )}
              </Section>
            )}

            {/* Traffic */}
            {node.packets !== undefined && (
              <Section title="Traffic">
                <Row label="Packets" value={node.packets.toLocaleString()} />
                {node.retries !== undefined && (
                  <Row label="Retries" value={
                    <span style={{ color: (node.retries ?? 0) > 50 ? '#ef4444' : 'inherit' }}>
                      {node.retries}
                    </span>
                  } />
                )}
                {node.data_tx !== undefined && node.data_tx > 0 && <Row label="TX" value={formatBytes(node.data_tx)} />}
                {node.data_rx !== undefined && node.data_rx > 0 && <Row label="RX" value={formatBytes(node.data_rx)} />}
              </Section>
            )}

            {/* Timestamps */}
            {(node.first_seen || node.last_seen) && (
              <Section title="Timestamps">
                {node.first_seen && <Row label="First seen" value={new Date(node.first_seen).toLocaleString()} />}
                {node.last_seen  && <Row label="Last seen"  value={new Date(node.last_seen).toLocaleString()}  />}
              </Section>
            )}

            {/* Probed SSIDs — Station only */}
            {node.group === 'station' && node.probedSSIDs && node.probedSSIDs.length > 0 && (
              <CollapsibleSection title={`Probed SSIDs (${node.probedSSIDs.length})`}>
                <SSIDList ssids={node.probedSSIDs} />
              </CollapsibleSection>
            )}

            {/* Observed SSIDs — AP only */}
            {node.group === 'ap' && node.observed_ssids && node.observed_ssids.length > 0 && (
              <Section title={`Observed SSIDs (${node.observed_ssids.length})`}>
                <SSIDList ssids={node.observed_ssids} />
              </Section>
            )}

            {/* Last ANonce — AP only */}
            {node.group === 'ap' && node.last_anonce && (
              <Section title="Last ANonce">
                <span className="ndp-anonce">{node.last_anonce}</span>
              </Section>
            )}

          </div>
        </>
      )}
    </div>
  );
};
