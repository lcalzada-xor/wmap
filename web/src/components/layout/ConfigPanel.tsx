import React, { useState, useEffect, useCallback } from 'react';
import ReactDOM from 'react-dom';
import { Collapsible } from '../ui/Collapsible';
import { Select } from '../ui/Select';
import { ScanIcon, HopperIcon, InterfaceIcon, PersistIcon, ChannelIcon } from '../icons/PanelIcons';
import { ChannelModal } from '../overlays/ChannelModal';
import { InterfaceModal } from '../overlays/InterfaceModal';
import type { ScanConfigState } from '../../hooks/useScanConfig';

interface ConfigPanelProps extends ScanConfigState {
  onSelectIface: (iface: string) => void;
  onApplyChannels: (channels: number[]) => void;
  onTogglePersistence: () => void;
}

function bandOf(ch: number): '2.4' | '5' | '6' {
  if (ch <= 14) return '2.4';
  if (ch <= 177) return '5';
  return '6';
}

const IFACE_MODAL_OFFSET = 24;

export const ConfigPanel: React.FC<ConfigPanelProps> = ({
  interfaces,
  selectedIface,
  hopperChannels,
  persistence,
  applying,
  loading,
  onSelectIface,
  onApplyChannels,
  onTogglePersistence,
}) => {
  const [pendingChannels, setPendingChannels] = useState<number[]>(hopperChannels);
  const [channelModalOpen, setChannelModalOpen] = useState(false);
  // Set of interface names whose detail modal is open
  const [openIfaceModals, setOpenIfaceModals] = useState<Set<string>>(new Set());

  useEffect(() => {
    setPendingChannels(hopperChannels);
  }, [hopperChannels]);

  const selectedIfaceInfo = interfaces.find(i => i.name === selectedIface) ?? null;
  const allSupportedChannels = selectedIfaceInfo?.capabilities.supported_channels ?? [];

  const ifaceOptions = interfaces.map(i => ({
    value: i.name,
    label: i.name,
    sublabel: i.capabilities.supported_bands.join(' · '),
  }));

  function togglePendingChannel(ch: number) {
    setPendingChannels(prev =>
      prev.includes(ch) ? prev.filter(c => c !== ch) : [...prev, ch]
    );
  }

  function toggleBand(band: string) {
    const bandChs = allSupportedChannels.filter(ch => bandOf(ch) === band);
    const allActive = bandChs.every(ch => pendingChannels.includes(ch));
    if (allActive) {
      setPendingChannels(prev => prev.filter(ch => !bandChs.includes(ch)));
    } else {
      setPendingChannels(prev => Array.from(new Set([...prev, ...bandChs])));
    }
  }

  function handleApply() {
    onApplyChannels(pendingChannels);
    setChannelModalOpen(false);
  }

  const toggleIfaceModal = useCallback((name: string) => {
    setOpenIfaceModals(prev => {
      const next = new Set(prev);
      if (next.has(name)) next.delete(name); else next.add(name);
      return next;
    });
  }, []);

  const closeIfaceModal = useCallback((name: string) => {
    setOpenIfaceModals(prev => {
      const next = new Set(prev);
      next.delete(name);
      return next;
    });
  }, []);

  const isDirty = JSON.stringify([...pendingChannels].sort()) !== JSON.stringify([...hopperChannels].sort());
  const hasChannels = allSupportedChannels.length > 0;

  // Stable ordered list so offsets don't shift when modals close
  const openIfaceList = interfaces.filter(i => openIfaceModals.has(i.name));

  return (
    <div className="config-panel-content">
      {loading && <div className="config-loading">Loading…</div>}

      <Collapsible label="Scan" icon={<ScanIcon />} defaultOpen>
        <div className="config-scan-section">
          <label className="config-toggle-row">
            <PersistIcon size={13} />
            <span className="config-toggle-label">Persistence</span>
            <button
              className={`config-toggle ${persistence ? 'on' : 'off'}`}
              onClick={onTogglePersistence}
              type="button"
              aria-pressed={persistence}
            >
              <span className="config-toggle-knob" />
            </button>
          </label>
        </div>
      </Collapsible>

      <Collapsible label="Channel Hopper" icon={<HopperIcon />} defaultOpen>
        <div className="config-hopper-section">
          {interfaces.length > 0 && (
            <div className="config-field">
              <span className="config-field-label">
                <InterfaceIcon size={11} />
                Interface
              </span>
              <Select
                options={ifaceOptions}
                value={selectedIface}
                onChange={onSelectIface}
                icon={<InterfaceIcon size={11} />}
                placeholder="Select interface"
                disabled={interfaces.length === 0}
              />
            </div>
          )}

          {hasChannels && (
            <button
              className={`config-channels-btn ${isDirty ? 'dirty' : ''}`}
              onClick={() => setChannelModalOpen(true)}
              type="button"
            >
              <ChannelIcon size={12} />
              <span className="config-channels-btn-label">Channels</span>
              <span className="config-channels-btn-badge">
                {pendingChannels.length}/{allSupportedChannels.length}
              </span>
              {isDirty && <span className="config-channels-btn-dot" />}
            </button>
          )}

          {interfaces.map(iface => {
            const isOpen = openIfaceModals.has(iface.name);
            return (
              <button
                key={iface.name}
                className={`config-channels-btn${isOpen ? ' active' : ''}`}
                onClick={() => toggleIfaceModal(iface.name)}
                type="button"
                title={isOpen ? `Close ${iface.name}` : `Inspect ${iface.name}`}
              >
                <InterfaceIcon size={12} />
                <span className="config-channels-btn-label">{iface.name}</span>
                <span className="config-channels-btn-badge">
                  {iface.capabilities.supported_bands.length} band{iface.capabilities.supported_bands.length !== 1 ? 's' : ''}
                </span>
                {isOpen && <span className="config-iface-open-dot" />}
              </button>
            );
          })}

          {interfaces.length === 0 && !loading && (
            <span className="config-empty">No interfaces detected</span>
          )}
        </div>
      </Collapsible>

      {ReactDOM.createPortal(
        <>
          {openIfaceList.map((iface, idx) => (
            <InterfaceModal
              key={iface.name}
              iface={iface}
              onClose={() => closeIfaceModal(iface.name)}
              initialOffset={idx * IFACE_MODAL_OFFSET}
            />
          ))}
          {channelModalOpen && (
            <ChannelModal
              allChannels={allSupportedChannels}
              pendingChannels={pendingChannels}
              onToggle={togglePendingChannel}
              onToggleBand={toggleBand}
              onApply={handleApply}
              onClose={() => setChannelModalOpen(false)}
              applying={applying}
              isDirty={isDirty}
              onSetChannels={setPendingChannels}
            />
          )}
        </>,
        document.body,
      )}
    </div>
  );
};
