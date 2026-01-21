/**
 * Graph Filter
 * Encapsulates filtering logic for the graph.
 */

import { Store } from '../core/store/store.js';
import { NodeGroups } from '../core/constants.js';
import { AttackTags } from '../core/attack_tags.js';

import { SaturationManager } from './saturation_manager.js';

export const GraphFilter = {
    /**
     * Main filter function - applies all active filters
     */
    apply(node) {
        // Saturation Protection (Critical Check)
        if (!SaturationManager.shouldShow(node.id)) return false;

        // Apply basic filters first (fast rejection)
        if (!this.applyBasicFilters(node)) return false;

        // Apply advanced filters
        if (!this.applyAdvancedFilters(node)) return false;

        return true;
    },

    /**
     * Basic filters (existing logic)
     */
    applyBasicFilters(node) {
        // Access State via Store
        const filters = Store.state.filters;

        // Type filters
        if (!filters.showAP && node.group === NodeGroups.AP) return false;
        if (!filters.showSta && node.group === NodeGroups.STATION) return false;

        // Legacy RSSI filter (kept for backwards compatibility)
        if (node.rssi !== undefined && node.rssi < filters.minRSSI) return false;

        // Persist Findings Logic
        if (!filters.persistFindings) {
            if (node.group === NodeGroups.NETWORK || node.group === NodeGroups.AP) return true;
            if (node.lastSeen) {
                if (Date.now() - new Date(node.lastSeen).getTime() > 60000) return false;
            }
        }

        return true;
    },

    /**
     * Advanced filters (new logic)
     */
    applyAdvancedFilters(node) {
        // Text search (multi-field with wildcard support)
        if (!this.filterByText(node)) return false;

        // Security filter
        if (!this.filterBySecurity(node)) return false;

        // Vulnerability filter
        if (!this.filterByVulnerability(node)) return false;

        // Frequency filter
        if (!this.filterByFrequency(node)) return false;

        // Channel filter
        if (!this.filterByChannel(node)) return false;

        // Vendor filter
        if (!this.filterByVendor(node)) return false;

        // Signal range filter
        if (!this.filterBySignalRange(node)) return false;

        // Time range filter
        if (!this.filterByTimeRange(node)) return false;

        // Traffic filter
        if (!this.filterByTraffic(node)) return false;

        const filters = Store.state.filters;

        // New Boolean Filters
        if (filters.hasHandshake && !node.has_handshake) return false;

        // Hidden SSID: SSID is empty, null, or undefined
        if (filters.hiddenSSID) {
            const ssid = node.ssid || '';
            if (ssid.trim() !== '') return false; // Only show nodes with empty SSID
        }

        // WPS Active: Check wps_info or capabilities
        if (filters.wpsActive) {
            const hasWPS = (node.wps_info && node.wps_info !== '') ||
                (node.capabilities && Array.isArray(node.capabilities) && node.capabilities.includes('WPS')) ||
                (typeof node.capabilities === 'string' && node.capabilities.includes('WPS'));
            if (!hasWPS) return false;
        }

        if (filters.randomizedMac && !node.is_randomized) return false;

        return true;
    },

    /**
     * Multi-field text search with wildcard support (*)
     */
    filterByText(node) {
        const filters = Store.state.filters;

        if (!filters.searchQuery || filters.searchQuery.length === 0) {
            return true;
        }

        const query = filters.searchQuery.toLowerCase();

        // Helper for wildcard matching
        const matches = (text, pattern) => {
            if (!text) return false;
            if (pattern.includes('*')) {
                const parts = pattern.split('*');
                // Simple wildcard implementation: check if all parts exist in order
                let currentIndex = 0;
                for (const part of parts) {
                    if (part === '') continue;
                    const foundIndex = text.indexOf(part, currentIndex);
                    if (foundIndex === -1) return false;
                    currentIndex = foundIndex + part.length;
                }
                return true;
            }
            return text.includes(pattern);
        };

        const label = (node.label || "").toLowerCase();
        const mac = (node.mac || "").toLowerCase();
        const ssid = (node.ssid || "").toLowerCase();
        const vendor = (node.vendor || "").toLowerCase();

        // Alias lookup via Store
        const alias = (Store.state.aliases[node.mac] || "").toLowerCase();

        return matches(label, query) ||
            matches(mac, query) ||
            matches(ssid, query) ||
            matches(vendor, query) ||
            matches(alias, query);
    },

    /**
     * Security type filter
     * Only filters nodes that HAVE security info
     */
    filterBySecurity(node) {
        const filters = Store.state.filters;
        if (!filters.security || filters.security.length === 0) {
            return true;
        }

        // If node doesn't have security info, show it (don't filter unknown)
        if (!node.security) return true;

        return filters.security.includes(node.security);
    },

    /**
     * Vulnerability filter
     */
    filterByVulnerability(node) {
        const filters = Store.state.filters;
        if (!filters.vulnerabilities || filters.vulnerabilities.length === 0) {
            return true;
        }

        const tags = AttackTags.getTags(node).map(t => t.label);

        // Check if node has ANY of the selected vulnerabilities
        return filters.vulnerabilities.some(v => tags.includes(v));
    },

    /**
     * Frequency filter (2.4GHz / 5GHz)
     * Only filters nodes that HAVE frequency info
     */
    filterByFrequency(node) {
        const filters = Store.state.filters;
        if (!filters.frequency || filters.frequency.length === 0) {
            return true;
        }

        // If node doesn't have frequency info, show it (don't filter unknown)
        if (!node.frequency && !node.freq) return true;

        const freq = node.frequency || node.freq;
        const freqGHz = freq / 1000; // Convert MHz to GHz

        // Check if frequency matches any selected band
        return filters.frequency.some(band => {
            if (band === '2.4') {
                return freqGHz >= 2.4 && freqGHz < 2.5;
            } else if (band === '5') {
                return freqGHz >= 5.0 && freqGHz < 6.0;
            }
            return false;
        });
    },

    /**
     * Channel filter
     * Only filters nodes that HAVE channel info
     */
    filterByChannel(node) {
        const filters = Store.state.filters;
        if (!filters.channels || filters.channels.length === 0) {
            return true;
        }

        // If node doesn't have channel info, show it (don't filter unknown)
        if (!node.channel) return true;

        return filters.channels.includes(node.channel);
    },

    /**
     * Vendor filter
     * Only filters nodes that HAVE vendor info
     */
    filterByVendor(node) {
        const filters = Store.state.filters;
        if (!filters.vendors || filters.vendors.length === 0) {
            return true;
        }

        // If node doesn't have vendor info, show it (don't filter unknown)
        if (!node.vendor) return true;

        return filters.vendors.includes(node.vendor);
    },

    /**
     * Signal range filter (custom RSSI range)
     */
    filterBySignalRange(node) {
        const filters = Store.state.filters;
        if (!filters.signalRange) return true;

        const { min, max } = filters.signalRange;

        // If default range, skip
        if (min === -100 && max === 0) return true;

        if (node.rssi === undefined) return false;

        return node.rssi >= min && node.rssi <= max;
    },

    /**
     * Time range filter (last seen)
     * IMPORTANT: Preserves graph relationships - Networks and APs are always shown
     * to maintain topology. Only Stations are filtered by time.
     */
    filterByTimeRange(node) {
        const filters = Store.state.filters;
        if (!filters.timeRange || !filters.timeRange.lastSeen) {
            return true;
        }

        // Always show Networks and APs to preserve graph topology
        if (node.group === NodeGroups.NETWORK || node.group === NodeGroups.AP) {
            return true;
        }

        // Only filter Stations by time
        if (!node.last_seen && !node.lastSeen) return false;

        const lastSeen = new Date(node.last_seen || node.lastSeen);
        const now = Date.now();
        const threshold = filters.timeRange.lastSeen; // milliseconds

        return (now - lastSeen.getTime()) <= threshold;
    },

    /**
     * Traffic filter (minimum TX/RX/packets)
     * IMPORTANT: Preserves graph relationships - Networks and APs are always shown
     * to maintain topology. Only Stations are filtered by traffic.
     */
    filterByTraffic(node) {
        const filters = Store.state.filters;
        if (!filters.traffic) return true;

        const { minTx, minRx, minPackets } = filters.traffic;

        // If all zero, skip
        if (minTx === 0 && minRx === 0 && minPackets === 0) return true;

        // Always show Networks and APs to preserve graph topology
        if (node.group === NodeGroups.NETWORK || node.group === NodeGroups.AP) {
            return true;
        }

        // Only filter Stations by traffic
        const tx = node.data_tx || 0;
        const rx = node.data_rx || 0;
        const packets = node.packets || 0;

        return tx >= minTx && rx >= minRx && packets >= minPackets;
    }
};
