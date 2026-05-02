import React from 'react';
import { Collapsible } from '../ui/Collapsible';
import { NodeTypeIcon, SignalIcon, LockIcon, ChannelIcon, ClockIcon } from '../icons/PanelIcons';
import type { FilterState } from '../../hooks/useFilters';

function MacIcon() {
  return (
    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <rect x="2" y="3" width="20" height="14" rx="2" />
      <path d="M8 21h8M12 17v4" />
    </svg>
  );
}

const RSSI_OPTIONS: { label: string; value: number | null }[] = [
  { label: 'All',              value: null },
  { label: '≥ Excellent (−55)', value: -55 },
  { label: '≥ Good (−65)',      value: -65 },
  { label: '≥ Fair (−75)',      value: -75 },
];

const ACTIVITY_OPTIONS: { label: string; value: number | null }[] = [
  { label: 'All',    value: null },
  { label: '1 min',  value: 60 },
  { label: '5 min',  value: 300 },
  { label: '15 min', value: 900 },
];

interface FilterPanelProps {
  filters: FilterState;
  availableChannels: number[];
  availableSecurities: string[];
  onToggleGroup: (group: 'ap' | 'station' | 'network') => void;
  onSetRssiMin: (value: number | null) => void;
  onSetSecurity: (value: string | null) => void;
  onToggleChannel: (ch: number) => void;
  onSetMacSearch: (value: string) => void;
  onSetActivityWindow: (value: number | null) => void;
  onReset: () => void;
}

function ActiveBadge() {
  return <span className="filter-count-badge">!</span>;
}

function CountBadge({ count }: { count: number }) {
  return <span className="filter-count-badge">{count}</span>;
}

export const FilterPanel: React.FC<FilterPanelProps> = ({
  filters,
  availableChannels,
  availableSecurities,
  onToggleGroup,
  onSetRssiMin,
  onSetSecurity,
  onToggleChannel,
  onSetMacSearch,
  onSetActivityWindow,
  onReset,
}) => {
  const hasActiveFilters =
    !filters.showAP ||
    !filters.showStation ||
    !filters.showNetwork ||
    filters.rssiMin !== null ||
    filters.security !== null ||
    filters.channels.length > 0 ||
    filters.macSearch !== '' ||
    filters.activityWindow !== null;

  return (
    <div className="filter-panel-content">
      <div className="filter-panel-header">
        {hasActiveFilters && (
          <button className="filter-reset-btn" onClick={onReset} title="Reset all filters">
            Reset
          </button>
        )}
      </div>

      <Collapsible
        label="Node Type"
        icon={<NodeTypeIcon />}
        defaultOpen
      >
        <div className="filter-type-group">
          <button
            className={`filter-type-btn ap ${filters.showAP ? 'active' : ''}`}
            onClick={() => onToggleGroup('ap')}
          >AP</button>
          <button
            className={`filter-type-btn sta ${filters.showStation ? 'active' : ''}`}
            onClick={() => onToggleGroup('station')}
          >STA</button>
          <button
            className={`filter-type-btn net ${filters.showNetwork ? 'active' : ''}`}
            onClick={() => onToggleGroup('network')}
          >Net</button>
        </div>
      </Collapsible>

      <Collapsible
        label="Recent Activity"
        icon={<ClockIcon />}
        badge={filters.activityWindow !== null ? <ActiveBadge /> : undefined}
        defaultOpen={false}
      >
        <div className="filter-activity-group">
          {ACTIVITY_OPTIONS.map(opt => (
            <button
              key={String(opt.value)}
              className={`filter-activity-btn ${filters.activityWindow === opt.value ? 'active' : ''}`}
              onClick={() => onSetActivityWindow(opt.value)}
            >
              {opt.label}
            </button>
          ))}
        </div>
      </Collapsible>

      <Collapsible
        label="Min. Signal"
        icon={<SignalIcon />}
        badge={filters.rssiMin !== null ? <ActiveBadge /> : undefined}
        defaultOpen={false}
      >
        <div className="filter-radio-group">
          {RSSI_OPTIONS.map(opt => (
            <label key={String(opt.value)} className="filter-radio-item">
              <span className={`filter-radio-dot ${filters.rssiMin === opt.value ? 'checked' : ''}`} />
              <input
                type="radio"
                name="rssiMin"
                checked={filters.rssiMin === opt.value}
                onChange={() => onSetRssiMin(opt.value)}
              />
              <span>{opt.label}</span>
            </label>
          ))}
        </div>
      </Collapsible>

      {availableSecurities.length > 0 && (
        <Collapsible
          label="Security"
          icon={<LockIcon />}
          badge={filters.security !== null ? <ActiveBadge /> : undefined}
          defaultOpen={false}
        >
          <div className="filter-radio-group">
            <label className="filter-radio-item">
              <span className={`filter-radio-dot ${filters.security === null ? 'checked' : ''}`} />
              <input
                type="radio"
                name="security"
                checked={filters.security === null}
                onChange={() => onSetSecurity(null)}
              />
              <span>All</span>
            </label>
            {availableSecurities.map(sec => (
              <label key={sec} className="filter-radio-item">
                <span className={`filter-radio-dot ${filters.security === sec ? 'checked' : ''}`} />
                <input
                  type="radio"
                  name="security"
                  checked={filters.security === sec}
                  onChange={() => onSetSecurity(sec)}
                />
                <span>{sec}</span>
              </label>
            ))}
          </div>
        </Collapsible>
      )}

      {availableChannels.length > 0 && (
        <Collapsible
          label="Channels"
          icon={<ChannelIcon />}
          badge={filters.channels.length > 0 ? <CountBadge count={filters.channels.length} /> : undefined}
          defaultOpen={false}
        >
          <div className="filter-channel-grid">
            {availableChannels.map(ch => (
              <button
                key={ch}
                className={`filter-channel-btn ${filters.channels.includes(ch) ? 'active' : ''}`}
                onClick={() => onToggleChannel(ch)}
              >
                {ch}
              </button>
            ))}
          </div>
        </Collapsible>
      )}

      <Collapsible
        label="MAC Search"
        icon={<MacIcon />}
        badge={filters.macSearch !== '' ? <ActiveBadge /> : undefined}
        defaultOpen={false}
      >
        <div className="filter-mac-search">
          <input
            className="filter-mac-input"
            type="text"
            placeholder="e.g. aa:bb or de:ad"
            value={filters.macSearch}
            onChange={e => onSetMacSearch(e.target.value)}
            spellCheck={false}
          />
          {filters.macSearch !== '' && (
            <button
              className="filter-mac-clear"
              onClick={() => onSetMacSearch('')}
              title="Clear"
            >
              ×
            </button>
          )}
        </div>
      </Collapsible>
    </div>
  );
};
