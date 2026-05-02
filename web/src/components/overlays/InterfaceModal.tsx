import React, { useEffect, useState, useCallback } from 'react';
import { InterfaceIcon } from '../icons/PanelIcons';
import { useDraggable } from '../../hooks/useDraggable';
import type { InterfaceInfo } from '../../hooks/useScanConfig';

const POLL_INTERVAL_MS = 1500;
const API_BASE = 'http://localhost:8080';

function useLiveIface(name: string, initial: InterfaceInfo): InterfaceInfo {
  const [iface, setIface] = useState<InterfaceInfo>(initial);

  const poll = useCallback(async () => {
    try {
      const res = await fetch(`${API_BASE}/api/interfaces`);
      if (!res.ok) return;
      const data = await res.json();
      const found: InterfaceInfo | undefined = (data.interfaces ?? []).find(
        (i: InterfaceInfo) => i.name === name,
      );
      if (found) setIface(found);
    } catch {
      // keep last known value on error
    }
  }, [name]);

  useEffect(() => {
    poll();
    const id = setInterval(poll, POLL_INTERVAL_MS);
    return () => clearInterval(id);
  }, [poll]);

  return iface;
}

function bandOf(ch: number): '2.4' | '5' | '6' {
  if (ch <= 14) return '2.4';
  if (ch <= 177) return '5';
  return '6';
}

const BAND_COLORS: Record<string, string> = {
  '2.4': 'var(--accent-cyan)',
  '5':   'var(--accent-amber)',
  '6':   'var(--accent-green)',
};

const BAND_LABELS: Record<string, string> = {
  '2.4GHz': '2.4 GHz',
  '5GHz':   '5 GHz',
  '6GHz':   '6 GHz',
};

const BAND_KEY: Record<string, string> = {
  '2.4GHz': '2.4',
  '5GHz':   '5',
  '6GHz':   '6',
};

const MODE_COLORS: Record<string, string> = {
  monitor: 'var(--accent-cyan)',
  managed: 'var(--accent-amber)',
  master:  'var(--accent-green)',
  'ad-hoc':'var(--accent-purple)',
};

function fmt(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000)     return `${(n / 1_000).toFixed(1)}K`;
  return String(n);
}

interface InterfaceModalProps {
  iface: InterfaceInfo;
  onClose: () => void;
  initialOffset?: number;
}

export const InterfaceModal: React.FC<InterfaceModalProps> = ({ iface: initialIface, onClose, initialOffset = 0 }) => {
  const { pos, onMouseDown } = useDraggable({ x: initialOffset, y: initialOffset });
  const iface = useLiveIface(initialIface.name, initialIface);
  const { capabilities, metrics } = iface;

  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if (e.key === 'Escape') onClose();
    }
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, [onClose]);

  const totalRx  = metrics.packets_received ?? 0;
  const totalDrop = metrics.packets_dropped ?? 0;
  const total     = totalRx + totalDrop;
  const dropRate  = total > 0 ? ((totalDrop / total) * 100).toFixed(1) : '0.0';
  const dropRateNum = parseFloat(dropRate);

  const channelsByBand = (capabilities.supported_bands ?? []).map(bandLabel => {
    const key = BAND_KEY[bandLabel] as '2.4' | '5' | '6';
    const all = (capabilities.supported_channels ?? []).filter(ch => bandOf(ch) === key);
    const active = (iface.current_channels ?? []).filter(ch => bandOf(ch) === key);
    return { bandLabel, key, all, active };
  });

  const modeColor = MODE_COLORS[capabilities.operation_mode ?? ''] ?? 'var(--text-secondary)';

  return (
    <div
      className="iface-modal"
      role="dialog"
      aria-modal="true"
      aria-label={`Interface details – ${iface.name}`}
      style={{ translate: `${pos.x}px ${pos.y}px` }}
    >
      {/* Header */}
      <div className="iface-modal-header" onMouseDown={onMouseDown} style={{ cursor: 'grab' }}>
          <div className="iface-modal-title-group">
            <span className="iface-modal-title">
              <InterfaceIcon size={13} />
              {iface.name}
            </span>
            <span className="iface-modal-mac">{iface.mac ?? '—'}</span>
          </div>
          <button className="channel-modal-close" onClick={onClose} type="button" aria-label="Close">
            ✕
          </button>
        </div>

        <div className="iface-modal-body">

          {/* Section 1 — Hardware Identity */}
          <div className="iface-modal-section">
            <span className="iface-modal-section-label">Hardware</span>
            <div className="iface-modal-rows">
              <div className="iface-modal-row">
                <span className="iface-modal-row-key">Driver</span>
                <span className="iface-modal-row-val mono">
                  {capabilities.driver_name ?? <span className="iface-modal-na">n/a</span>}
                </span>
              </div>
              <div className="iface-modal-row">
                <span className="iface-modal-row-key">Mode</span>
                <span
                  className="iface-modal-badge"
                  style={{ '--badge-color': modeColor } as React.CSSProperties}
                >
                  {capabilities.operation_mode ?? 'unknown'}
                </span>
              </div>
              <div className="iface-modal-row">
                <span className="iface-modal-row-key">TX Power</span>
                <span className="iface-modal-row-val">
                  {capabilities.tx_power != null
                    ? <><span className="iface-modal-val-num">{capabilities.tx_power}</span> <span className="iface-modal-unit">dBm</span></>
                    : <span className="iface-modal-na">n/a</span>}
                </span>
              </div>
            </div>
          </div>

          {/* Section 2 — Frequency Bands */}
          {(capabilities.supported_bands?.length ?? 0) > 0 && (
            <div className="iface-modal-section">
              <span className="iface-modal-section-label">Supported Bands</span>
              <div className="iface-modal-bands">
                {(capabilities.supported_bands ?? []).map(b => {
                  const key = BAND_KEY[b];
                  const color = BAND_COLORS[key] ?? 'var(--text-secondary)';
                  return (
                    <span
                      key={b}
                      className="iface-modal-band-badge"
                      style={{ '--band-color': color } as React.CSSProperties}
                    >
                      {BAND_LABELS[b] ?? b}
                    </span>
                  );
                })}
              </div>
            </div>
          )}

          {/* Section 3 — Channel Coverage */}
          {channelsByBand.length > 0 && (
            <div className="iface-modal-section">
              <span className="iface-modal-section-label">Channel Coverage</span>
              <div className="iface-modal-coverage">
                {channelsByBand.map(({ bandLabel, key, all, active }) => {
                  const color = BAND_COLORS[key] ?? 'var(--text-secondary)';
                  const pct = all.length > 0 ? (active.length / all.length) * 100 : 0;
                  return (
                    <div key={bandLabel} className="iface-modal-band-row">
                      <div className="iface-modal-band-row-header">
                        <span className="iface-modal-band-name" style={{ color }}>
                          {BAND_LABELS[bandLabel] ?? bandLabel}
                        </span>
                        <span className="iface-modal-band-count">
                          <span style={{ color }}>{active.length}</span>
                          <span className="iface-modal-band-sep">/</span>
                          <span>{all.length}</span>
                          <span className="iface-modal-unit"> ch hopping</span>
                        </span>
                      </div>
                      <div className="iface-modal-bar-track">
                        <div
                          className="iface-modal-bar-fill"
                          style={{ width: `${pct}%`, background: color } as React.CSSProperties}
                        />
                      </div>
                      {active.length > 0 && (
                        <div className="iface-modal-active-channels">
                          {active.map(ch => {
                            const isCurrent = ch === iface.current_channel && iface.current_channel !== 0;
                            return (
                              <span
                                key={ch}
                                className={`iface-modal-ch-chip${isCurrent ? ' iface-modal-ch-chip--active' : ''}`}
                                style={{ '--chip-color': isCurrent ? 'var(--accent-red)' : color } as React.CSSProperties}
                              >
                                {ch}
                              </span>
                            );
                          })}
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {/* Section 4 — Live Metrics */}
          <div className="iface-modal-section">
            <span className="iface-modal-section-label">Live Metrics</span>
            <div className="iface-modal-metrics">
              <div className="iface-modal-metric">
                <span className="iface-modal-metric-val" style={{ color: 'var(--accent-green)' }}>
                  {fmt(totalRx)}
                </span>
                <span className="iface-modal-metric-label">Received</span>
              </div>
              <div className="iface-modal-metric-divider" />
              <div className="iface-modal-metric">
                <span
                  className="iface-modal-metric-val"
                  style={{ color: dropRateNum > 5 ? 'var(--accent-red)' : 'var(--accent-amber)' }}
                >
                  {fmt(totalDrop)}
                </span>
                <span className="iface-modal-metric-label">Dropped</span>
              </div>
              <div className="iface-modal-metric-divider" />
              <div className="iface-modal-metric">
                <span
                  className="iface-modal-metric-val"
                  style={{ color: dropRateNum > 5 ? 'var(--accent-red)' : 'var(--text-secondary)' }}
                >
                  {dropRate}<span className="iface-modal-unit">%</span>
                </span>
                <span className="iface-modal-metric-label">Drop Rate</span>
              </div>
            </div>
          </div>

        </div>
    </div>
  );
};

