/**
 * Filter UI Controller
 * Manages the advanced filter panel UI and interactions.
 */

import { State } from '../core/state.js';
import { FilterManager } from '../core/filter_manager.js';
import { html } from '../core/html.js';
import { EventBus } from '../core/event_bus.js';
import { Events } from '../core/constants.js';
import { FilterTemplates } from './filter_templates.js';

export const FilterUI = {
    nodesDataSet: null,

    init(nodesDataSet) {
        this.nodesDataSet = nodesDataSet;

        this.bindSearchBar();
        this.bindAdvancedFilters();
        this.bindPresets();
        this.loadSearchHistory();

        // Initial Render
        this.updateFilterTags();

        // Reactivity: Subscribe to State changes
        State.subscribe('filters', () => {
            this.updateFilterTags();
            this.syncUIWithState();
            // Debounce graph refresh? The graph handles it.
            EventBus.emit(Events.SEARCH, null);
        });

        State.subscribe('activePreset', () => this.renderPresets());
    },

    /**
     * Bind search bar with autocomplete
     */
    bindSearchBar() {
        const input = document.getElementById('node-search');
        const btnClear = document.getElementById('btn-clear-search');
        const btnToggle = document.getElementById('btn-toggle-filters');
        const suggestions = document.getElementById('search-suggestions');

        if (!input) return;

        // Debounced search
        let timeout;
        input.addEventListener('input', (e) => {
            clearTimeout(timeout);
            const query = e.target.value;

            timeout = setTimeout(() => {
                // This assignment triggers the Proxy -> State.notify -> EventBus.emit
                State.filters.searchQuery = query;
                this.handleSearch(query);
                this.showSuggestions(query);
            }, 300);
        });

        // Clear button
        if (btnClear) {
            btnClear.addEventListener('click', () => {
                input.value = '';
                State.filters.searchQuery = '';
                this.hideSuggestions();
                // State update triggers refresh
                // this.updateFilterTags();
                // if (this.refreshCallback) this.refreshCallback('search', '');
            });
        }

        // Toggle advanced filters
        if (btnToggle) {
            btnToggle.addEventListener('click', () => {
                this.toggleAdvancedPanel();
            });
        }

        // Hide suggestions when clicking outside
        document.addEventListener('click', (e) => {
            if (!input.contains(e.target) && !suggestions.contains(e.target)) {
                this.hideSuggestions();
            }
        });
    },

    /**
     * Handle search query
     */
    handleSearch(query) {
        if (query && query.length > 0) {
            FilterManager.addToSearchHistory(query);
        }
    },

    /**
     * Show autocomplete suggestions
     */
    showSuggestions(query) {
        if (!query || query.length < 2) {
            this.hideSuggestions();
            return;
        }

        const suggestions = FilterManager.getSuggestions(query, 'all', this.nodesDataSet);
        const container = document.getElementById('search-suggestions');

        if (!container || suggestions.length === 0) {
            this.hideSuggestions();
            return;
        }

        container.innerHTML = '';
        suggestions.forEach(item => {
            const div = document.createElement('div');
            div.className = 'suggestion-item';

            if (typeof item === 'object') {
                div.innerHTML = FilterTemplates.suggestionItem(item);
                div.addEventListener('click', () => {
                    document.getElementById('node-search').value = item.value;
                    State.filters.searchQuery = item.value;
                    this.hideSuggestions();
                });
            } else {
                div.innerHTML = FilterTemplates.suggestionItem(item);
                div.addEventListener('click', () => {
                    document.getElementById('node-search').value = item;
                    State.filters.searchQuery = item;
                    this.hideSuggestions();
                });
            }

            container.appendChild(div);
        });

        container.classList.add('active');
    },

    /**
     * Hide suggestions dropdown
     */
    hideSuggestions() {
        const container = document.getElementById('search-suggestions');
        if (container) {
            container.classList.remove('active');
        }
    },

    /**
     * Toggle advanced filters panel
     */
    toggleAdvancedPanel() {
        const panel = document.getElementById('advanced-filters-panel');
        if (!panel) return;

        if (panel.style.display === 'none' || !panel.style.display) {
            panel.style.display = 'block';
            setTimeout(() => panel.classList.add('active'), 10);
        } else {
            panel.classList.remove('active');
            setTimeout(() => panel.style.display = 'none', 300);
        }
    },

    /**
     * Bind advanced filter controls
     */
    bindAdvancedFilters() {
        // Security checkboxes
        document.querySelectorAll('.filter-security').forEach(cb => {
            cb.addEventListener('change', () => {
                this.updateArrayFilter('security', cb.value, cb.checked);
            });
        });

        // Vulnerability checkboxes
        document.querySelectorAll('.filter-vulnerability').forEach(cb => {
            cb.addEventListener('change', () => {
                this.updateArrayFilter('vulnerabilities', cb.value, cb.checked);
            });
        });

        // Frequency checkboxes
        document.querySelectorAll('.filter-frequency').forEach(cb => {
            cb.addEventListener('change', () => {
                this.updateArrayFilter('frequency', cb.value, cb.checked);
            });
        });

        // Boolean filters (New)
        document.querySelectorAll('.filter-boolean').forEach(cb => {
            cb.addEventListener('change', () => {
                State.filters[cb.value] = cb.checked;
            });
        });

        // Channel multi-select
        const channelSelect = document.getElementById('filter-channels');
        if (channelSelect) {
            channelSelect.addEventListener('change', () => {
                const selected = Array.from(channelSelect.selectedOptions).map(opt => parseInt(opt.value));
                State.filters.channels = selected;
            });
        }

        // Quick select common 2.4GHz channels (1, 6, 11)
        const btnCommon24 = document.getElementById('btn-select-common-24');
        if (btnCommon24 && channelSelect) {
            btnCommon24.addEventListener('click', () => {
                const commonChannels = [1, 6, 11];
                // UI update via syncUIWithState (triggered by State change) is safer but we can update DOM optimistically
                // Actually, State change -> syncUIWithState -> loop over options -> update selected.
                // So we just set state.
                State.filters.channels = commonChannels;
            });
        }

        // Clear channels button
        const btnClearChannels = document.getElementById('btn-clear-channels');
        if (btnClearChannels && channelSelect) {
            btnClearChannels.addEventListener('click', () => {
                State.filters.channels = [];
            });
        }

        // Vendor multi-select
        const vendorSelect = document.getElementById('filter-vendor');
        if (vendorSelect) {
            vendorSelect.addEventListener('change', () => {
                const selected = Array.from(vendorSelect.selectedOptions).map(opt => opt.value);
                State.filters.vendors = selected;
            });
        }

        // Signal range inputs
        const rssiMin = document.getElementById('rssi-min');
        const rssiMax = document.getElementById('rssi-max');
        if (rssiMin && rssiMax) {
            const updateRange = () => {
                State.filters.signalRange = {
                    min: parseInt(rssiMin.value) || -100,
                    max: parseInt(rssiMax.value) || 0
                };
                this.updateFilterTags();
                if (this.refreshCallback) this.refreshCallback('signalRange', State.filters.signalRange);
            };
            rssiMin.addEventListener('change', updateRange);
            rssiMax.addEventListener('change', updateRange);
        }

        // Time range preset
        const timeRange = document.getElementById('time-range-preset');
        if (timeRange) {
            timeRange.addEventListener('change', (e) => {
                const value = e.target.value;
                let ms = null;

                switch (value) {
                    case '5m': ms = 5 * 60 * 1000; break;
                    case '15m': ms = 15 * 60 * 1000; break;
                    case '1h': ms = 60 * 60 * 1000; break;
                    case '24h': ms = 24 * 60 * 60 * 1000; break;
                    case 'custom':
                        const input = prompt("Enter minutes (e.g. 10) or hours (e.g. 1h):", "10");
                        if (input) {
                            // Simple parser
                            let val = parseInt(input);
                            if (input.toLowerCase().includes('h')) {
                                val = parseFloat(input) * 60;
                            }
                            if (!isNaN(val) && val > 0) {
                                ms = val * 60 * 1000;
                            }
                        }
                        break;
                    default: ms = null;
                }

                State.filters.timeRange.lastSeen = ms;
                this.updateFilterTags();
                if (this.refreshCallback) this.refreshCallback('timeRange', ms);
            });
        }

        // Traffic inputs
        const trafficTx = document.getElementById('traffic-min-tx');
        const trafficRx = document.getElementById('traffic-min-rx');
        const trafficPackets = document.getElementById('traffic-min-packets');

        const updateTraffic = () => {
            State.filters.traffic = {
                minTx: parseInt(trafficTx?.value) || 0,
                minRx: parseInt(trafficRx?.value) || 0,
                minPackets: parseInt(trafficPackets?.value) || 0
            };
            this.updateFilterTags();
            if (this.refreshCallback) this.refreshCallback('traffic', State.filters.traffic);
        };

        if (trafficTx) trafficTx.addEventListener('change', updateTraffic);
        if (trafficRx) trafficRx.addEventListener('change', updateTraffic);
        if (trafficPackets) trafficPackets.addEventListener('change', updateTraffic);

        // Reset button
        const btnReset = document.getElementById('btn-reset-filters');
        if (btnReset) {
            btnReset.addEventListener('click', () => {
                this.resetAllFilters();
            });
        }

        // Save preset button
        const btnSave = document.getElementById('btn-save-preset');
        if (btnSave) {
            btnSave.addEventListener('click', () => {
                const name = prompt('Enter preset name:');
                if (name) {
                    FilterManager.saveCustomPreset(name);
                    alert(`Preset "${name}" saved!`);
                    this.renderPresets(); // Refresh preset buttons
                }
            });
        }
    },

    /**
     * Update array-based filter
     */
    updateArrayFilter(filterName, value, checked) {
        let newArray = [...State.filters[filterName]];

        if (checked) {
            if (!newArray.includes(value)) {
                newArray.push(value);
            }
        } else {
            newArray = newArray.filter(v => v !== value);
        }

        // Assignment triggers State proxy -> Reactivity
        State.filters[filterName] = newArray;
    },

    /**
     * Bind preset buttons
     */
    bindPresets() {
        this.renderPresets();
    },

    /**
     * Render preset buttons
     */
    renderPresets() {
        const container = document.querySelector('.preset-buttons');
        if (!container) return;

        container.innerHTML = '';
        const presets = FilterManager.getAllPresets();

        Object.keys(presets).forEach(id => {
            const preset = presets[id];
            const btn = document.createElement('button');
            btn.className = 'preset-btn';
            btn.dataset.preset = id;
            btn.innerHTML = FilterTemplates.presetButtonContent(preset);

            if (State.filters.activePreset === id) {
                btn.classList.add('active');
            }

            btn.addEventListener('click', () => {
                FilterManager.applyPreset(id);
                // State update triggers refresh

                // Update active state locally or let renderPresets handle if fully reactive
                container.querySelectorAll('.preset-btn').forEach(b => b.classList.remove('active'));
                btn.classList.add('active');
            });

            container.appendChild(btn);
        });
    },

    /**
     * Sync UI controls with State
     */
    syncUIWithState() {
        // Update checkboxes
        document.querySelectorAll('.filter-security').forEach(cb => {
            cb.checked = State.filters.security.includes(cb.value);
        });

        document.querySelectorAll('.filter-vulnerability').forEach(cb => {
            cb.checked = State.filters.vulnerabilities.includes(cb.value);
        });

        document.querySelectorAll('.filter-frequency').forEach(cb => {
            cb.checked = State.filters.frequency.includes(cb.value);
        });

        // Update boolean filters
        document.querySelectorAll('.filter-boolean').forEach(cb => {
            cb.checked = State.filters[cb.value] === true;
        });

        // Update search input
        const searchInput = document.getElementById('node-search');
        if (searchInput) {
            searchInput.value = State.filters.searchQuery || '';
        }

        // Update signal range
        const rssiMin = document.getElementById('rssi-min');
        const rssiMax = document.getElementById('rssi-max');
        if (rssiMin) rssiMin.value = State.filters.signalRange.min;
        if (rssiMax) rssiMax.value = State.filters.signalRange.max;

        // Update channel multi-select
        const channelSelect = document.getElementById('filter-channels');
        if (channelSelect) {
            Array.from(channelSelect.options).forEach(opt => {
                opt.selected = State.filters.channels.includes(parseInt(opt.value));
            });
        }

        // Update vendor multi-select
        const vendorSelect = document.getElementById('filter-vendor');
        if (vendorSelect) {
            Array.from(vendorSelect.options).forEach(opt => {
                opt.selected = State.filters.vendors.includes(opt.value);
            });
        }
    },

    /**
     * Render filter tags/chips
     */
    bindFilterTags() {
        this.updateFilterTags();
    },

    /**
     * Update filter tags display
     */
    /**
     * Update filter tags display (Optimized for DOM Performance)
     */
    updateFilterTags() {
        const container = document.getElementById('filter-tags');
        if (!container) return;

        // Collect all active filters into a unified list of objects
        // { id: 'type-value', type: 'Type', value: 'Value', onRemove: fn }
        const activeTags = [];

        // Helper to generate unique ID
        const getId = (type, val) => `tag-${type}-${val}`.replace(/\s+/g, '-').toLowerCase();

        // Search
        if (State.filters.searchQuery && State.filters.searchQuery.length > 0) {
            activeTags.push({
                id: getId('search', 'query'),
                type: 'Search',
                value: State.filters.searchQuery,
                onRemove: () => {
                    document.getElementById('node-search').value = '';
                    State.filters.searchQuery = '';
                    this.updateFilterTags();
                    if (this.refreshCallback) this.refreshCallback('search', '');
                }
            });
        }

        // Boolean Filters
        const booleanFilters = [
            { key: 'hasHandshake', label: 'Handshake' },
            { key: 'hiddenSSID', label: 'Hidden SSID' },
            { key: 'wpsActive', label: 'WPS' },
            { key: 'randomizedMac', label: 'Randomized' }
        ];

        booleanFilters.forEach(f => {
            if (State.filters[f.key]) {
                activeTags.push({
                    id: getId('status', f.key),
                    type: 'Status',
                    value: f.label,
                    onRemove: () => {
                        State.filters[f.key] = false;
                        this.syncUIWithState();
                        this.updateFilterTags();
                        if (this.refreshCallback) this.refreshCallback(f.key, false);
                    }
                });
            }
        });

        // Security
        State.filters.security.forEach(sec => {
            activeTags.push({
                id: getId('security', sec),
                type: 'Security',
                value: sec,
                onRemove: () => {
                    State.filters.security = State.filters.security.filter(s => s !== sec);
                    this.syncUIWithState();
                    this.updateFilterTags();
                    if (this.refreshCallback) this.refreshCallback('security', State.filters.security);
                }
            });
        });

        // Vulnerabilities
        State.filters.vulnerabilities.forEach(vuln => {
            activeTags.push({
                id: getId('vuln', vuln),
                type: 'Vuln',
                value: vuln,
                onRemove: () => {
                    State.filters.vulnerabilities = State.filters.vulnerabilities.filter(v => v !== vuln);
                    this.syncUIWithState();
                    this.updateFilterTags();
                    if (this.refreshCallback) this.refreshCallback('vulnerabilities', State.filters.vulnerabilities);
                }
            });
        });

        // Frequency
        State.filters.frequency.forEach(freq => {
            activeTags.push({
                id: getId('frequency', freq),
                type: 'Frequency',
                value: `${freq} GHz`,
                onRemove: () => {
                    State.filters.frequency = State.filters.frequency.filter(f => f !== freq);
                    this.syncUIWithState();
                    this.updateFilterTags();
                    if (this.refreshCallback) this.refreshCallback('frequency', State.filters.frequency);
                }
            });
        });

        // Vendor
        State.filters.vendors.forEach(vendor => {
            activeTags.push({
                id: getId('vendor', vendor),
                type: 'Vendor',
                value: vendor,
                onRemove: () => {
                    State.filters.vendors = State.filters.vendors.filter(v => v !== vendor);
                    this.syncUIWithState();
                    this.updateFilterTags();
                    if (this.refreshCallback) this.refreshCallback('vendor', State.filters.vendors);
                }
            });
        });

        // Channel
        State.filters.channels.forEach(channel => {
            activeTags.push({
                id: getId('channel', channel),
                type: 'Channel',
                value: channel.toString(),
                onRemove: () => {
                    State.filters.channels = State.filters.channels.filter(c => c !== channel);
                    const channelSelect = document.getElementById('filter-channels');
                    if (channelSelect) {
                        Array.from(channelSelect.options).forEach(opt => {
                            if (parseInt(opt.value) === channel) opt.selected = false;
                        });
                    }
                    this.updateFilterTags();
                    if (this.refreshCallback) this.refreshCallback('channels', State.filters.channels);
                }
            });
        });

        // Signal Range
        if (State.filters.signalRange.min !== -100 || State.filters.signalRange.max !== 0) {
            activeTags.push({
                id: getId('signal', 'range'),
                type: 'Signal',
                value: `${State.filters.signalRange.min} to ${State.filters.signalRange.max} dBm`,
                onRemove: () => {
                    State.filters.signalRange = { min: -100, max: 0 };
                    this.syncUIWithState();
                    this.updateFilterTags();
                    if (this.refreshCallback) this.refreshCallback('signalRange', State.filters.signalRange);
                }
            });
        }

        // Time Range
        if (State.filters.timeRange.lastSeen) {
            const minutes = State.filters.timeRange.lastSeen / (60 * 1000);
            let label = `${minutes}m`;
            if (minutes >= 60) label = `${minutes / 60}h`;

            activeTags.push({
                id: getId('time', 'range'),
                type: 'Time',
                value: `Last ${label}`,
                onRemove: () => {
                    State.filters.timeRange.lastSeen = null;
                    this.syncUIWithState();
                    this.updateFilterTags();
                    if (this.refreshCallback) this.refreshCallback('timeRange', null);
                }
            });
        }

        // RECONCILIATION
        const existingTags = Array.from(container.children);
        const existingIds = new Set(existingTags.map(el => el.dataset.tagId));
        const newIds = new Set(activeTags.map(t => t.id));

        // 1. Remove tags that are no longer active
        existingTags.forEach(el => {
            if (!newIds.has(el.dataset.tagId)) {
                el.remove();
            }
        });

        // 2. Add new tags
        activeTags.forEach(tagData => {
            if (!existingIds.has(tagData.id)) {
                this.addFilterTag(container, tagData.type, tagData.value, tagData.onRemove, tagData.id);
            } else {
                // Optional: Update value if it changed (e.g., search text update)
                // For simple tags ID usually implies value, but search text might change while ID stays 'tag-search-query' if logic above isn't granular enough.
                // In my logic above, search ID is static 'tag-search-query', so we SHOULD update text.
                const el = container.querySelector(`[data-tag-id="${tagData.id}"]`);
                if (el) {
                    const span = el.querySelector('span');
                    if (span) span.innerHTML = `<strong>${tagData.type}:</strong> ${tagData.value}`;
                }
            }
        });

        this.updateActiveFiltersCount();
    },

    /**
     * Add a filter tag chip
     */
    /**
     * Add a filter tag chip
     */
    addFilterTag(container, type, value, onRemove, id = null) {
        const tag = document.createElement('div');
        tag.className = 'filter-tag';
        if (id) tag.dataset.tagId = id;

        tag.innerHTML = FilterTemplates.filterTag(type, value);

        tag.querySelector('.remove').addEventListener('click', onRemove);
        container.appendChild(tag);
    },

    /**
     * Update active filters count badge
     */
    updateActiveFiltersCount() {
        const badge = document.getElementById('active-filters-count');
        if (!badge) return;

        const count = FilterManager.getActiveFiltersCount();
        badge.textContent = count;
        badge.style.display = count > 0 ? 'block' : 'none';
    },

    /**
     * Reset all filters
     */
    resetAllFilters() {
        FilterManager.resetFilters();
        // Trigger Reactivity forcefully if resetFilters modifies State in place?
        // FilterManager probably modifies 'State.filters' object references. 
        // If FilterManager does `State.filters.x = y`, it triggers proxy.
        // If it does `State.filters = default`, we lost the proxy if not handled carefully (State.filters is const? No it is object property).
        // Check core/filter_manager.js later. Assuming it sets properties.

        // Use notify to be sure if FilterManager replaces the whole object without triggering setters
        // But for now let's assume it sets values.

        // Manual cleanup of inputs that might not be fully two-way bound yet (legacy inputs)
        // syncUIWithState handles validation/logic, but let's ensure reset propagates.

        // Actually, if we reset via State, syncUIWithState called by listener will clear inputs.
        // We just need to ensure FilterManager triggers the Proxy setters.
        State.notify('filters', State.filters);
    },

    /**
     * Load search history
     */
    loadSearchHistory() {
        FilterManager.loadSearchHistory();
    },

    /**
     * Populate vendor dropdown with unique vendors
     */
    populateVendorDropdown() {
        const select = document.getElementById('filter-vendor');
        if (!select || !this.nodesDataSet) return;

        const vendors = FilterManager.getUniqueVendors(this.nodesDataSet);
        select.innerHTML = '';

        vendors.forEach(vendor => {
            const option = document.createElement('option');
            option.value = vendor;
            option.textContent = vendor;
            select.appendChild(option);
        });
    },

    /**
     * Populate channel dropdown with unique channels
     */
    populateChannelDropdown() {
        const select = document.getElementById('filter-channels');
        if (!select || !this.nodesDataSet) return;

        const channels = new Set();
        const nodes = this.nodesDataSet.get();

        nodes.forEach(node => {
            if (node.channel) {
                channels.add(node.channel);
            }
        });

        const sortedChannels = Array.from(channels).sort((a, b) => a - b);

        // Keep current selection
        const currentSelection = State.filters.channels || [];

        select.innerHTML = '';

        sortedChannels.forEach(channel => {
            const option = document.createElement('option');
            option.value = channel;
            option.textContent = `Channel ${channel}`;
            option.selected = currentSelection.includes(channel);
            select.appendChild(option);
        });
    }
};
