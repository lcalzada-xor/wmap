/**
 * HUD Controller
 * Manages sidebar controls and event listeners.
 */

import { Store } from '../core/store/store.js';
import { Actions } from '../core/store/actions.js';
import { API } from '../core/api.js';
import { Notifications } from './notifications.js';
import { HUDTemplates } from './hud_templates.js';
import { Utils } from '../core/utils.js';

export const HUD = {
    init(refreshCallback, actionCallback) {
        this.refreshCallback = refreshCallback;
        this.actionCallback = actionCallback;
        this.bindToggles();
        this.bindSearch();
        this.bindActionButtons();
        this.bindDetailsEvents();
    },

    bindToggles() {
        const bind = (id, prop, isConfig = false) => {
            const el = document.getElementById(id);
            if (!el) return;

            // Set initial state
            // Store values
            const config = Store.state.config;
            const filters = Store.state.filters;

            el.checked = isConfig ? config[prop] : filters[prop];

            el.onchange = (e) => {
                const val = e.target.checked;

                if (isConfig) {
                    Store.dispatch(Actions.CONFIG_UPDATED, { key: prop, value: val });
                    // Explicitly dispatch logic for specific configs if needed (or rely on listeners in other modules)
                    // e.g. ui:physics is now handled by Store subscription in main.js, wait.. no
                    // main.js was subscribing to EventBus for 'ui:physics'.. we need to update main.js OR 
                    // make this dispatch emit legacy events too? 
                    // Better: Update consumers to subscribe to CONFIG_UPDATED or we add legacy bridging here.
                    // For now, let's keep it pure Store. 

                    // Legacy Bridge for things that listen to EventBus 'ui:physics'
                    EventBus.emit(`ui:${prop}`, val);
                } else {
                    Store.dispatch(Actions.FILTER_UPDATED, { key: prop, value: val });
                    EventBus.emit('graph:refresh');
                }

                // Specific Logic
                if (id === 'toggle-persist') { // Sync with backend
                    API.request(`/api/config/persistence?enabled=${val}`, { method: 'POST' })
                        .then(() => {
                            Notifications.show('Persistence setting updated', 'success');
                        })
                        .catch(error => {
                            console.error('Failed to update persistence:', error);

                            // Revert UI state on failure
                            if (Store.state.filters.persistFindings !== !val) {
                                Store.dispatch(Actions.FILTER_UPDATED, { key: 'persistFindings', value: !val });
                                EventBus.emit('graph:refresh');
                            }

                            if (error.status === 403) {
                                Notifications.show('Insufficient permissions', 'danger');
                            } else if (error.status === 401) {
                                // Redirect handled by API wrapper
                            } else {
                                Notifications.show('Failed to update setting', 'danger');
                            }
                        });
                }
            };
        };

        bind('toggle-grid', 'grid', true);
        bind('toggle-trails', 'trails', true);
        bind('toggle-heatmap', 'heatmap', true);
        bind('toggle-physics', 'physics', true); // Physics is special, usually tied to network options

        bind('filter-ap', 'showAP');
        bind('filter-sta', 'showSta');
        bind('toggle-physics', 'physics', true); // Physics is special, usually tied to network options

        const btnStabilize = document.getElementById('btn-stabilize');
        if (btnStabilize) {
            btnStabilize.onclick = () => {
                if (this.refreshCallback) this.refreshCallback('stabilize'); // This will need refactoring
                Notifications.show("Stabilizing network view...", "info");
            };
        }

        bind('filter-ap', 'showAP');
        bind('filter-sta', 'showSta');
        bind('toggle-persist', 'persistFindings');

        // RSSI Slider
        const slider = document.getElementById('rssi-slider');
        const valLabel = document.getElementById('rssi-val');
        if (slider) {
            slider.oninput = () => {
                const v = parseInt(slider.value);
                valLabel.innerText = v;
                Store.dispatch(Actions.FILTER_UPDATED, { key: 'minRSSI', value: v });
                EventBus.emit('graph:refresh');
            };
        }
    },

    bindSearch() {
        const searchInput = document.getElementById('node-search');
        if (searchInput) {
            searchInput.oninput = (e) => {
                Store.dispatch(Actions.FILTER_UPDATED, { key: 'searchQuery', value: e.target.value });
                EventBus.emit('graph:refresh');
            };
        }
    },

    bindActionButtons() {
        const btnClear = document.getElementById('btn-clear-workspace');
        if (btnClear) {
            btnClear.onclick = () => {
                if (confirm("Clear all workspace data? This cannot be undone.")) {
                    API.clearWorkspace().then(() => {
                        Notifications.show("Workspace Cleared", "success");
                        // Ideally trigger a graph clear here too
                        if (this.refreshCallback) this.refreshCallback('clear');
                    });
                }
            };
        }

        const btnScan = document.getElementById('btn-active-scan');
        if (btnScan) {
            btnScan.onclick = () => {
                API.triggerScan().then(() => Notifications.show("Active Scan Initiated", "success"))
                    .catch(err => Notifications.show(err.message, "danger"));
            };
        }

        // Zoom Controls
        // These need access to the network instance. 
        // We can expose a method to register zoom handlers or pass them in init.
    },

    bindDetailsEvents() {
        const content = document.getElementById('details-content');
        if (!content) return;

        content.addEventListener('click', (e) => {
            const btn = e.target.closest('[data-action]');
            if (!btn) return;

            const action = btn.dataset.action;
            const data = { ...btn.dataset };
            delete data.action; // Clean up

            if (action === 'copy-id') {
                this.copyToClipboard(data.text);
            } else if (action === 'open-handshakes') {
                // Determine MAC from data binding or node object. 
                // The template uses node props. 'data-action' button needs Mac context?
                // Template check: <button ... data-action="open-handshakes">
                // It doesn't have data-mac attached in template? Let's check.
                // Re-viewing template... "Open Captures Folder" button has NO data-mac.
                // We need to fetch MAC from the panel header or use the data attached to the button if present.
                // Actually the button is inside 'details-panel'. We can store the current NODE in HUD.
                if (this.currentNode) {
                    API.openHandshakeFolder(this.currentNode.mac)
                        .then(() => Notifications.show("Folder opened", "success"))
                        .catch(err => Notifications.show("Failed to open folder: " + err.message, "danger"));
                }
            } else if (this.actionCallback) {
                this.actionCallback(action, data);
            }
        });
    },

    updateStats(apCount, staCount) {
        document.getElementById('stat-ap').innerText = apCount;
        document.getElementById('stat-sta').innerText = staCount;
    },

    showDetails(node) {
        const panel = document.getElementById('details-panel');
        const content = document.getElementById('details-content');
        const btnClose = document.getElementById('btn-close-details');

        if (!panel || !content) return;

        this.currentNode = node;

        // Close Handler
        if (btnClose) btnClose.onclick = () => this.hideDetails();

        // Helper formatters passed to template
        const formatters = {
            formatBytes: Utils.formatBytes,
            timeAgo: Utils.timeAgo
        };

        // Use Template
        content.innerHTML = HUDTemplates.detailsPanel(node, formatters);

        panel.classList.add('active');
    },

    hideDetails() {
        const panel = document.getElementById('details-panel');
        if (panel) panel.classList.remove('active');
    },

    copyToClipboard(text) {
        navigator.clipboard.writeText(text).then(() => {
            Notifications.show("Copied to clipboard", "success");
        });
    }
};
