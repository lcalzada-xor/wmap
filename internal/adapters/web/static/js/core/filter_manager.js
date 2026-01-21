/**
 * Filter Manager
 * Centralized service for filter management, presets, and business logic.
 */

import { Store } from './store/store.js';
import { Actions } from './store/actions.js';

export const FilterManager = {
    // Predefined Quick Filters
    PRESETS: {
        'all': {
            name: 'All Devices',
            icon: 'fa-globe',
            filters: {
                showAP: true,
                showSta: true,
                security: [],
                frequency: [],
                channels: [],
                vendors: [],
                signalRange: { min: -100, max: 0 },
                timeRange: { lastSeen: null },
                traffic: { minTx: 0, minRx: 0, minPackets: 0 }
            }
        },
        'aps-only': {
            name: 'Access Points',
            icon: 'fa-wifi',
            filters: {
                showAP: true,
                showSta: false,
                security: [],
                frequency: [],
                channels: [],
                vendors: [],
                signalRange: { min: -100, max: 0 },
                timeRange: { lastSeen: null },
                traffic: { minTx: 0, minRx: 0, minPackets: 0 }
            }
        },
        'strong-signal': {
            name: 'Strong Signal',
            icon: 'fa-signal',
            filters: {
                showAP: true,
                showSta: true,
                security: [],
                frequency: [],
                channels: [],
                vendors: [],
                signalRange: { min: -60, max: 0 },
                timeRange: { lastSeen: null },
                traffic: { minTx: 0, minRx: 0, minPackets: 0 }
            }
        },
        'wpa2-only': {
            name: 'WPA2 Networks',
            icon: 'fa-shield-alt',
            filters: {
                showAP: true,
                showSta: true,
                security: ['WPA2'],
                frequency: [],
                channels: [],
                vendors: [],
                signalRange: { min: -100, max: 0 },
                timeRange: { lastSeen: null },
                traffic: { minTx: 0, minRx: 0, minPackets: 0 }
            }
        },
        '5ghz-only': {
            name: '5GHz Only',
            icon: 'fa-broadcast-tower',
            filters: {
                showAP: true,
                showSta: true,
                security: [],
                frequency: ['5'],
                channels: [],
                vendors: [],
                signalRange: { min: -100, max: 0 },
                timeRange: { lastSeen: null },
                traffic: { minTx: 0, minRx: 0, minPackets: 0 }
            }
        },
        'recent': {
            name: 'Recent Activity',
            icon: 'fa-clock',
            filters: {
                showAP: true,
                showSta: true,
                security: [],
                frequency: [],
                channels: [],
                vendors: [],
                signalRange: { min: -100, max: 0 },
                timeRange: { lastSeen: 300000 }, // 5 minutes in ms
                traffic: { minTx: 0, minRx: 0, minPackets: 0 }
            }
        }
    },

    /**
     * Apply a predefined preset
     */
    applyPreset(presetId) {
        const preset = this.PRESETS[presetId];
        if (!preset) {
            console.warn(`Preset ${presetId} not found`);
            return false;
        }

        // Apply all filters from preset
        // We use BATCH update to avoid multiple event emissions
        const updates = {
            ...preset.filters,
            activePreset: presetId,
            searchQuery: '' // Clear search when applying preset
        };

        Store.dispatch(Actions.FILTER_BATCH_UPDATED, updates);
        return true;
    },

    /**
     * Get count of active filters (non-default)
     */
    getActiveFiltersCount() {
        let count = 0;
        const filters = Store.state.filters;

        // Search query
        if (filters.searchQuery && filters.searchQuery.length > 0) count++;

        // Type filters (if not both enabled)
        if (!filters.showAP || !filters.showSta) count++;

        // Security
        if (filters.security && filters.security.length > 0) count++;

        // Frequency
        if (filters.frequency && filters.frequency.length > 0) count++;

        // Channels
        if (filters.channels && filters.channels.length > 0) count++;

        // Vendors
        if (filters.vendors && filters.vendors.length > 0) count++;

        // Signal range (if not default)
        if (filters.signalRange &&
            (filters.signalRange.min !== -100 || filters.signalRange.max !== 0)) {
            count++;
        }

        // Time range
        if (filters.timeRange && filters.timeRange.lastSeen) count++;

        // Traffic
        if (filters.traffic &&
            (filters.traffic.minTx > 0 ||
                filters.traffic.minRx > 0 ||
                filters.traffic.minPackets > 0)) {
            count++;
        }

        // RSSI (legacy, if not default)
        if (filters.minRSSI && filters.minRSSI !== -100) count++;

        return count;
    },

    /**
     * Get autocomplete suggestions for a given field
     */
    getSuggestions(query, field, nodesDataSet) {
        if (!query || query.length < 2) return [];

        const suggestions = new Set();
        const lowerQuery = query.toLowerCase();

        // Get all nodes from the dataset
        const nodes = nodesDataSet ? nodesDataSet.get() : [];

        nodes.forEach(node => {
            switch (field) {
                case 'vendor':
                    if (node.vendor && node.vendor.toLowerCase().includes(lowerQuery)) {
                        suggestions.add(node.vendor);
                    }
                    break;
                case 'ssid':
                    if (node.ssid && node.ssid.toLowerCase().includes(lowerQuery)) {
                        suggestions.add(node.ssid);
                    }
                    break;
                case 'mac':
                    if (node.mac && node.mac.toLowerCase().includes(lowerQuery)) {
                        suggestions.add(node.mac);
                    }
                    break;
                case 'all':
                    // Multi-field search
                    if (node.vendor && node.vendor.toLowerCase().includes(lowerQuery)) {
                        suggestions.add({ type: 'vendor', value: node.vendor, icon: 'fa-industry' });
                    }
                    if (node.ssid && node.ssid.toLowerCase().includes(lowerQuery)) {
                        suggestions.add({ type: 'ssid', value: node.ssid, icon: 'fa-wifi' });
                    }
                    if (node.mac && node.mac.toLowerCase().includes(lowerQuery)) {
                        suggestions.add({ type: 'mac', value: node.mac, icon: 'fa-hashtag' });
                    }
                    if (node.label && node.label.toLowerCase().includes(lowerQuery)) {
                        suggestions.add({ type: 'label', value: node.label, icon: 'fa-tag' });
                    }
                    break;
            }
        });

        return Array.from(suggestions).slice(0, 10); // Limit to 10 suggestions
    },

    /**
     * Get unique vendors from dataset
     */
    getUniqueVendors(nodesDataSet) {
        const vendors = new Set();
        const nodes = nodesDataSet ? nodesDataSet.get() : [];

        nodes.forEach(node => {
            if (node.vendor && node.vendor !== 'Unknown') {
                vendors.add(node.vendor);
            }
        });

        return Array.from(vendors).sort();
    },

    /**
     * Get unique security types from dataset
     */
    getUniqueSecurityTypes(nodesDataSet) {
        const types = new Set();
        const nodes = nodesDataSet ? nodesDataSet.get() : [];

        nodes.forEach(node => {
            if (node.security) {
                types.add(node.security);
            }
        });

        return Array.from(types).sort();
    },

    /**
     * Reset all filters to default
     */
    resetFilters() {
        const defaults = {
            showAP: true,
            showSta: true,
            persistFindings: true,
            minRSSI: -100,
            searchQuery: '',
            security: [],
            frequency: [],
            channels: [],
            vendors: [],
            signalRange: { min: -100, max: 0 },
            timeRange: { lastSeen: null },
            traffic: { minTx: 0, minRx: 0, minPackets: 0 },

            // Reset boolean filters
            hasHandshake: false,
            hiddenSSID: false,
            wpsActive: false,
            randomizedMac: false,

            activePreset: null
        };

        Store.dispatch(Actions.FILTER_BATCH_UPDATED, defaults);
    },

    /**
     * Save current filters as a custom preset
     */
    saveCustomPreset(name) {
        const customPresets = this.getCustomPresets();
        const id = `custom_${Date.now()}`;

        customPresets[id] = {
            name: name,
            icon: 'fa-star',
            filters: { ...Store.state.filters }
        };

        localStorage.setItem('wmap_custom_presets', JSON.stringify(customPresets));
        return id;
    },

    /**
     * Get custom presets from localStorage
     */
    getCustomPresets() {
        const stored = localStorage.getItem('wmap_custom_presets');
        return stored ? JSON.parse(stored) : {};
    },

    /**
     * Delete a custom preset
     */
    deleteCustomPreset(id) {
        const customPresets = this.getCustomPresets();
        delete customPresets[id];
        localStorage.setItem('wmap_custom_presets', JSON.stringify(customPresets));
    },

    /**
     * Get all presets (built-in + custom)
     */
    getAllPresets() {
        return {
            ...this.PRESETS,
            ...this.getCustomPresets()
        };
    },

    /**
     * Export current filters as JSON
     */
    exportFilters() {
        return JSON.stringify(Store.state.filters, null, 2);
    },

    /**
     * Import filters from JSON
     */
    importFilters(json) {
        try {
            const filters = JSON.parse(json);
            Store.dispatch(Actions.FILTER_BATCH_UPDATED, filters);
            return true;
        } catch (e) {
            console.error('Failed to import filters:', e);
            return false;
        }
    },

    /**
     * Add search query to history
     */
    addToSearchHistory(query) {
        if (!query || query.length === 0) return;

        const filters = Store.state.filters;
        const history = filters.searchHistory || [];

        // Remove duplicates
        const filtered = history.filter(q => q !== query);

        // Add to beginning
        filtered.unshift(query);

        // Keep only last 10
        const newHistory = filtered.slice(0, 10);

        // Update State
        Store.dispatch(Actions.FILTER_UPDATED, { key: 'searchHistory', value: newHistory });

        // Persist to localStorage
        localStorage.setItem('wmap_search_history', JSON.stringify(newHistory));
    },

    /**
     * Load search history from localStorage
     */
    loadSearchHistory() {
        const stored = localStorage.getItem('wmap_search_history');
        if (stored) {
            const history = JSON.parse(stored);
            Store.dispatch(Actions.FILTER_UPDATED, { key: 'searchHistory', value: history });
        }
    }
};
