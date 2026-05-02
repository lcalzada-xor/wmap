import { useState, useMemo } from 'react';
import type { GraphData, GraphGroup } from '../types/graph';

export interface FilterState {
  showAP: boolean;
  showStation: boolean;
  showNetwork: boolean;
  rssiMin: number | null;
  security: string | null;
  channels: number[];
  macSearch: string;
  activityWindow: number | null;
}

const DEFAULT_FILTERS: FilterState = {
  showAP: true,
  showStation: true,
  showNetwork: true,
  rssiMin: null,
  security: null,
  channels: [],
  macSearch: '',
  activityWindow: null,
};

export function useFilters(graphData: GraphData | null) {
  const [filters, setFilters] = useState<FilterState>(DEFAULT_FILTERS);

  const availableChannels = useMemo<number[]>(() => {
    if (!graphData) return [];
    const set = new Set<number>();
    graphData.nodes.forEach(n => { if (n.channel) set.add(n.channel); });
    return Array.from(set).sort((a, b) => a - b);
  }, [graphData]);

  const availableSecurities = useMemo<string[]>(() => {
    if (!graphData) return [];
    const set = new Set<string>();
    graphData.nodes.forEach(n => { if (n.security) set.add(n.security); });
    return Array.from(set).sort();
  }, [graphData]);

  const filteredData = useMemo<GraphData | null>(() => {
    if (!graphData) return null;

    const groupVisible: Record<GraphGroup, boolean> = {
      ap: filters.showAP,
      station: filters.showStation,
      network: filters.showNetwork,
    };

    const macQuery = filters.macSearch.trim().toLowerCase();

    const now = Date.now();

    const visibleNodes = graphData.nodes.filter(n => {
      if (!groupVisible[n.group]) return false;
      if (filters.rssiMin !== null && n.rssi !== undefined && n.rssi < filters.rssiMin) return false;
      if (filters.security && n.security && n.security !== filters.security) return false;
      if (filters.channels.length > 0 && n.channel && !filters.channels.includes(n.channel)) return false;
      if (macQuery && !(n.mac?.toLowerCase().includes(macQuery))) return false;
      if (filters.activityWindow !== null) {
        if (!n.last_seen) return false;
        const lastSeenMs = new Date(n.last_seen).getTime();
        if (isNaN(lastSeenMs) || now - lastSeenMs > filters.activityWindow * 1000) return false;
      }
      return true;
    });

    const visibleIds = new Set(visibleNodes.map(n => n.id));
    const visibleEdges = graphData.edges.filter(e => visibleIds.has(e.from) && visibleIds.has(e.to));

    return { nodes: visibleNodes, edges: visibleEdges, config: graphData.config };
  }, [graphData, filters]);

  function toggleGroup(group: 'ap' | 'station' | 'network') {
    setFilters(f => ({
      ...f,
      showAP:      group === 'ap'      ? !f.showAP      : f.showAP,
      showStation: group === 'station' ? !f.showStation : f.showStation,
      showNetwork: group === 'network' ? !f.showNetwork : f.showNetwork,
    }));
  }

  function setRssiMin(value: number | null) {
    setFilters(f => ({ ...f, rssiMin: value }));
  }

  function setSecurity(value: string | null) {
    setFilters(f => ({ ...f, security: value }));
  }

  function toggleChannel(ch: number) {
    setFilters(f => {
      const next = f.channels.includes(ch) ? f.channels.filter(c => c !== ch) : [...f.channels, ch];
      return { ...f, channels: next };
    });
  }

  function setMacSearch(value: string) {
    setFilters(f => ({ ...f, macSearch: value }));
  }

  function setActivityWindow(value: number | null) {
    setFilters(f => ({ ...f, activityWindow: value }));
  }

  function resetFilters() {
    setFilters(DEFAULT_FILTERS);
  }

  return {
    filters,
    filteredData,
    availableChannels,
    availableSecurities,
    toggleGroup,
    setRssiMin,
    setSecurity,
    toggleChannel,
    setMacSearch,
    setActivityWindow,
    resetFilters,
  };
}
