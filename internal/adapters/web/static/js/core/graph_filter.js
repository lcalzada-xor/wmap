/**
 * Graph Filter
 * Encapsulates filtering logic for the graph.
 */

import { State } from '../core/state.js';

export const GraphFilter = {
    /**
     * Main filter function - applies all active filters
     */
    apply(node) {
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
        // Type filters
        if (!State.filters.showAP && node.group === 'ap') return false;
        if (!State.filters.showSta && node.group === 'station') return false;

        // Legacy RSSI filter (kept for backwards compatibility)
        if (node.rssi !== undefined && node.rssi < State.filters.minRSSI) return false;

        // Persist Findings Logic
        if (!State.filters.persistFindings) {
            if (node.group === 'network' || node.group === 'ap') return true;
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
        // Text search (multi-field)
        if (!this.filterByText(node)) return false;

        // Security filter
        if (!this.filterBySecurity(node)) return false;

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

        return true;
    },

    /**
     * Multi-field text search
     */
    filterByText(node) {
        if (!State.filters.searchQuery || State.filters.searchQuery.length === 0) {
            return true;
        }

        const q = State.filters.searchQuery.toLowerCase();
        const label = (node.label || "").toLowerCase();
        const mac = (node.mac || "").toLowerCase();
        const ssid = (node.ssid || "").toLowerCase();
        const vendor = (node.vendor || "").toLowerCase();
        const alias = (State.getAlias(node.mac) || "").toLowerCase();

        return label.includes(q) ||
            mac.includes(q) ||
            ssid.includes(q) ||
            vendor.includes(q) ||
            alias.includes(q);
    },

    /**
     * Security type filter
     */
    filterBySecurity(node) {
        if (!State.filters.security || State.filters.security.length === 0) {
            return true;
        }

        if (!node.security) return false;

        return State.filters.security.includes(node.security);
    },

    /**
     * Frequency filter (2.4GHz / 5GHz)
     */
    filterByFrequency(node) {
        if (!State.filters.frequency || State.filters.frequency.length === 0) {
            return true;
        }

        if (!node.frequency && !node.freq) return false;

        const freq = node.frequency || node.freq;
        const freqGHz = freq / 1000; // Convert MHz to GHz

        // Check if frequency matches any selected band
        return State.filters.frequency.some(band => {
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
     */
    filterByChannel(node) {
        if (!State.filters.channels || State.filters.channels.length === 0) {
            return true;
        }

        if (!node.channel) return false;

        return State.filters.channels.includes(node.channel);
    },

    /**
     * Vendor filter
     */
    filterByVendor(node) {
        if (!State.filters.vendors || State.filters.vendors.length === 0) {
            return true;
        }

        if (!node.vendor) return false;

        return State.filters.vendors.includes(node.vendor);
    },

    /**
     * Signal range filter (custom RSSI range)
     */
    filterBySignalRange(node) {
        if (!State.filters.signalRange) return true;

        const { min, max } = State.filters.signalRange;

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
        if (!State.filters.timeRange || !State.filters.timeRange.lastSeen) {
            return true;
        }

        // Always show Networks and APs to preserve graph topology
        if (node.group === 'network' || node.group === 'ap') {
            return true;
        }

        // Only filter Stations by time
        if (!node.last_seen && !node.lastSeen) return false;

        const lastSeen = new Date(node.last_seen || node.lastSeen);
        const now = Date.now();
        const threshold = State.filters.timeRange.lastSeen; // milliseconds

        return (now - lastSeen.getTime()) <= threshold;
    },

    /**
     * Traffic filter (minimum TX/RX/packets)
     * IMPORTANT: Preserves graph relationships - Networks and APs are always shown
     * to maintain topology. Only Stations are filtered by traffic.
     */
    filterByTraffic(node) {
        if (!State.filters.traffic) return true;

        const { minTx, minRx, minPackets } = State.filters.traffic;

        // If all zero, skip
        if (minTx === 0 && minRx === 0 && minPackets === 0) return true;

        // Always show Networks and APs to preserve graph topology
        if (node.group === 'network' || node.group === 'ap') {
            return true;
        }

        // Only filter Stations by traffic
        const tx = node.data_tx || 0;
        const rx = node.data_rx || 0;
        const packets = node.packets || 0;

        return tx >= minTx && rx >= minRx && packets >= minPackets;
    }
};
