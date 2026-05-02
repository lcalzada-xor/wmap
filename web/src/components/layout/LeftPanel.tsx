import React, { useState } from 'react';
import { FilterPanel } from './FilterPanel';
import { ConfigPanel } from './ConfigPanel';
import type { FilterState } from '../../hooks/useFilters';
import type { ScanConfigState } from '../../hooks/useScanConfig';

type PanelTab = 'config' | 'filters';

interface LeftPanelProps {
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

  scanConfig: ScanConfigState;
  onSelectIface: (iface: string) => void;
  onApplyChannels: (channels: number[]) => void;
  onTogglePersistence: () => void;
}

export const LeftPanel: React.FC<LeftPanelProps> = ({
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
  scanConfig,
  onSelectIface,
  onApplyChannels,
  onTogglePersistence,
}) => {
  const [activeTab, setActiveTab] = useState<PanelTab>('filters');

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
    <div className="left-panel glass-panel">
      <div className="left-panel-tabs">
        <button
          className={`left-panel-tab ${activeTab === 'config' ? 'active' : ''}`}
          onClick={() => setActiveTab('config')}
          type="button"
        >
          Config
        </button>
        <button
          className={`left-panel-tab ${activeTab === 'filters' ? 'active' : ''}`}
          onClick={() => setActiveTab('filters')}
          type="button"
        >
          Filters
          {hasActiveFilters && <span className="left-panel-tab-dot" />}
        </button>
      </div>

      <div className="left-panel-body">
        {activeTab === 'config' ? (
          <ConfigPanel
            {...scanConfig}
            onSelectIface={onSelectIface}
            onApplyChannels={onApplyChannels}
            onTogglePersistence={onTogglePersistence}
          />
        ) : (
          <FilterPanel
            filters={filters}
            availableChannels={availableChannels}
            availableSecurities={availableSecurities}
            onToggleGroup={onToggleGroup}
            onSetRssiMin={onSetRssiMin}
            onSetSecurity={onSetSecurity}
            onToggleChannel={onToggleChannel}
            onSetMacSearch={onSetMacSearch}
            onSetActivityWindow={onSetActivityWindow}
            onReset={onReset}
          />
        )}
      </div>
    </div>
  );
};
