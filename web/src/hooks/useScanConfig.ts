import { useState, useEffect, useCallback } from 'react';

const API_BASE = 'http://localhost:8080';

export interface InterfaceInfo {
  name: string;
  mac: string;
  capabilities: {
    supported_bands: string[];
    supported_channels: number[];
    driver_name?: string;
    tx_power?: number;
    operation_mode?: string;
  };
  current_channels: number[];
  current_channel: number;
  metrics: {
    packets_received: number;
    packets_dropped: number;
  };
}

export interface ScanConfigState {
  interfaces: InterfaceInfo[];
  selectedIface: string | null;
  hopperChannels: number[];
  persistence: boolean;
  applying: boolean;
  loading: boolean;
  error: string | null;
}

async function apiFetch(path: string, options?: RequestInit) {
  const res = await fetch(`${API_BASE}${path}`, options);
  if (!res.ok) throw new Error(`API error ${res.status}`);
  return res.json();
}

export function useScanConfig() {
  const [state, setState] = useState<ScanConfigState>({
    interfaces: [],
    selectedIface: null,
    hopperChannels: [],
    persistence: false,
    applying: false,
    loading: true,
    error: null,
  });

  const load = useCallback(async () => {
    setState(s => ({ ...s, loading: true, error: null }));
    try {
      const [ifaceRes, channelRes, configRes] = await Promise.all([
        apiFetch('/api/interfaces'),
        apiFetch('/api/channels'),
        apiFetch('/api/config'),
      ]);

      const interfaces: InterfaceInfo[] = ifaceRes.interfaces ?? [];
      const firstIface = interfaces[0]?.name ?? null;

      setState(s => ({
        ...s,
        interfaces,
        selectedIface: s.selectedIface ?? firstIface,
        hopperChannels: channelRes.channels ?? [],
        persistence: configRes.persistenceEnabled ?? false,
        loading: false,
      }));
    } catch (e) {
      setState(s => ({ ...s, loading: false, error: (e as Error).message }));
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  const selectIface = useCallback(async (iface: string) => {
    setState(s => ({ ...s, selectedIface: iface }));
    try {
      const res = await apiFetch(`/api/channels?interface=${encodeURIComponent(iface)}`);
      setState(s => ({ ...s, hopperChannels: res.channels ?? [] }));
    } catch {
      // Keep existing channels on error
    }
  }, []);

  const applyChannels = useCallback(async (channels: number[]) => {
    setState(s => ({ ...s, applying: true, error: null }));
    try {
      await apiFetch('/api/channels', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          interface: state.selectedIface ?? undefined,
          channels,
        }),
      });
      setState(s => ({ ...s, hopperChannels: channels, applying: false }));
    } catch (e) {
      setState(s => ({ ...s, applying: false, error: (e as Error).message }));
    }
  }, [state.selectedIface]);

  const togglePersistence = useCallback(async () => {
    const next = !state.persistence;
    try {
      await apiFetch(`/api/config/persistence?enabled=${next}`, { method: 'POST' });
      setState(s => ({ ...s, persistence: next }));
    } catch (e) {
      setState(s => ({ ...s, error: (e as Error).message }));
    }
  }, [state.persistence]);

  return {
    ...state,
    selectIface,
    applyChannels,
    togglePersistence,
    reload: load,
  };
}
