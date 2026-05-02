import React, { useEffect } from 'react';
import { ChannelIcon } from '../icons/PanelIcons';
import { useDraggable } from '../../hooks/useDraggable';

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

// Most commonly used / popular channels per band
const POPULAR_CHANNELS: Record<string, number[]> = {
  '2.4': [1, 6, 11],
  '5':   [36, 40, 44, 48, 149, 153, 157, 161],
  '6':   [1, 5, 9, 13, 17, 21, 25, 29],
};

// DFS channels in 5 GHz (require radar detection)
const DFS_CHANNELS_5G = new Set([
  52, 56, 60, 64,
  100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144,
]);

interface ChannelPattern {
  id: string;
  label: string;
  description: string;
  getChannels: (all: number[]) => number[];
}

const PATTERNS: ChannelPattern[] = [
  {
    id: 'all',
    label: 'All',
    description: 'Select all available channels',
    getChannels: (all) => [...all],
  },
  {
    id: 'none',
    label: 'None',
    description: 'Deselect all channels',
    getChannels: () => [],
  },
  {
    id: 'popular',
    label: 'Popular',
    description: 'Most-used channels (1, 6, 11 · 36-48 · 149-161)',
    getChannels: (all) =>
      all.filter(ch => {
        const band = bandOf(ch);
        return POPULAR_CHANNELS[band]?.includes(ch);
      }),
  },
  {
    id: 'non_dfs',
    label: 'Non-DFS',
    description: 'Exclude DFS channels — faster hopping, no radar wait',
    getChannels: (all) => all.filter(ch => !DFS_CHANNELS_5G.has(ch)),
  },
  {
    id: 'dfs',
    label: 'DFS only',
    description: 'Only DFS channels (5 GHz radar bands)',
    getChannels: (all) => all.filter(ch => DFS_CHANNELS_5G.has(ch)),
  },
  {
    id: 'low_2g',
    label: '2.4 only',
    description: 'Only 2.4 GHz band',
    getChannels: (all) => all.filter(ch => bandOf(ch) === '2.4'),
  },
  {
    id: 'high_5g',
    label: '5 GHz only',
    description: 'Only 5 GHz band',
    getChannels: (all) => all.filter(ch => bandOf(ch) === '5'),
  },
];

interface ChannelModalProps {
  allChannels: number[];
  pendingChannels: number[];
  onToggle: (ch: number) => void;
  onToggleBand: (band: string) => void;
  onApply: () => void;
  onClose: () => void;
  applying: boolean;
  isDirty: boolean;
  onSetChannels?: (channels: number[]) => void;
}

export const ChannelModal: React.FC<ChannelModalProps> = ({
  allChannels,
  pendingChannels,
  onToggle,
  onToggleBand,
  onApply,
  onClose,
  applying,
  isDirty,
  onSetChannels,
}) => {
  const { pos, onMouseDown } = useDraggable();

  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if (e.key === 'Escape') onClose();
    }
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, [onClose]);

  function applyPattern(pattern: ChannelPattern) {
    if (!onSetChannels) return;
    onSetChannels(pattern.getChannels(allChannels));
  }

  const bands = Array.from(new Set(allChannels.map(bandOf)));

  return (
    <div
      className="channel-modal"
      role="dialog"
      aria-modal="true"
      aria-label="Channel selector"
      style={{ translate: `${pos.x}px ${pos.y}px` }}
    >
      <div className="channel-modal-header" onMouseDown={onMouseDown} style={{ cursor: 'grab' }}>
          <span className="channel-modal-title">
            <ChannelIcon size={13} />
            Hopper Channels
          </span>
          <div className="channel-modal-header-right">
            <span className="channel-modal-summary">
              {pendingChannels.length}/{allChannels.length} active
            </span>
            <button
              className="channel-modal-close"
              onClick={onClose}
              type="button"
              aria-label="Close"
            >
              ✕
            </button>
          </div>
        </div>

        {/* Band toggles */}
        <div className="channel-modal-band-toggles">
          {bands.map(band => {
            const chs = allChannels.filter(ch => bandOf(ch) === band);
            const activeCount = chs.filter(ch => pendingChannels.includes(ch)).length;
            const allActive = activeCount === chs.length;
            const someActive = activeCount > 0 && !allActive;
            const color = BAND_COLORS[band];
            return (
              <button
                key={band}
                className={`channel-band-toggle ${allActive ? 'all-active' : someActive ? 'some-active' : ''}`}
                style={{ '--band-color': color } as React.CSSProperties}
                onClick={() => onToggleBand(band)}
                type="button"
                title={`Toggle all ${band} GHz (${activeCount}/${chs.length})`}
              >
                <span className="band-toggle-dot" />
                <span className="band-toggle-label">{band} GHz</span>
                <span className="band-toggle-count">{activeCount}/{chs.length}</span>
              </button>
            );
          })}
        </div>

        {/* Quick pattern presets */}
        <div className="channel-modal-patterns">
          <span className="channel-modal-patterns-label">Presets</span>
          <div className="channel-modal-patterns-list">
            {PATTERNS.filter(p => {
              if (p.id === 'dfs' || p.id === 'non_dfs')
                return allChannels.some(ch => DFS_CHANNELS_5G.has(ch));
              if (p.id === 'high_5g') return bands.includes('5');
              if (p.id === 'low_2g') return bands.includes('2.4');
              return true;
            }).map(pattern => (
              <button
                key={pattern.id}
                className="channel-pattern-btn"
                onClick={() => applyPattern(pattern)}
                type="button"
                title={pattern.description}
              >
                {pattern.label}
              </button>
            ))}
          </div>
        </div>

        <div className="channel-modal-body">
          {bands.map(band => {
            const chs = allChannels.filter(ch => bandOf(ch) === band);
            const color = BAND_COLORS[band];
            const popularSet = new Set(POPULAR_CHANNELS[band] ?? []);
            return (
              <div key={band} className="channel-modal-band">
                <div className="channel-modal-grid">
                  {chs.map(ch => {
                    const active = pendingChannels.includes(ch);
                    const isPopular = popularSet.has(ch);
                    const isDFS = DFS_CHANNELS_5G.has(ch);
                    return (
                      <button
                        key={ch}
                        className={`channel-modal-ch-btn ${active ? 'active' : ''} ${isPopular ? 'popular' : ''}`}
                        style={active ? { borderColor: color, color } : {}}
                        onClick={() => onToggle(ch)}
                        type="button"
                        title={[
                          `Channel ${ch}`,
                          isPopular ? '★ popular' : '',
                          isDFS ? '⚡ DFS' : '',
                        ].filter(Boolean).join(' · ')}
                      >
                        {ch}
                        {isPopular && <span className="ch-popular-dot" style={{ background: color }} />}
                        {isDFS && <span className="ch-dfs-marker">D</span>}
                      </button>
                    );
                  })}
                </div>
              </div>
            );
          })}
        </div>

        <div className="channel-modal-footer">
          <button
            className="channel-modal-cancel"
            onClick={onClose}
            type="button"
          >
            Cancel
          </button>
          <button
            className={`channel-modal-apply ${isDirty ? 'dirty' : ''} ${applying ? 'loading' : ''}`}
            onClick={onApply}
            disabled={applying || !isDirty}
            type="button"
          >
            {applying ? 'Applying…' : isDirty ? `Apply (${pendingChannels.length})` : 'No changes'}
          </button>
        </div>
    </div>
  );
};

