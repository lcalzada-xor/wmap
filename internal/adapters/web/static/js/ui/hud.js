/**
 * HUD Controller
 * Manages sidebar controls and event listeners.
 */

import { State } from '../core/state.js';
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
            el.checked = isConfig ? State.config[prop] : State.filters[prop];

            el.onchange = () => {
                const val = el.checked;
                if (isConfig) State.config[prop] = val;
                else State.filters[prop] = val;

                // Specific Logic
                if (id === 'toggle-persist') { // Sync with backend
                    API.request(`/api/config/persistence?enabled=${val}`, { method: 'POST' })
                        .then(() => {
                            Notifications.show('Persistence setting updated', 'success');
                        })
                        .catch(error => {
                            console.error('Failed to update persistence:', error);

                            // Revert UI state on failure
                            el.checked = !val;
                            State.filters.persistFindings = !val;

                            if (error.status === 403) {
                                Notifications.show('Insufficient permissions', 'danger');
                            } else if (error.status === 401) {
                                // Redirect handled by API wrapper
                            } else {
                                Notifications.show('Failed to update setting', 'danger');
                            }
                        });
                }

                if (this.refreshCallback) this.refreshCallback(prop, val);
            };
        };

        bind('toggle-grid', 'grid', true);
        bind('toggle-trails', 'trails', true);
        bind('toggle-heatmap', 'heatmap', true);
        bind('toggle-physics', 'physics', true); // Physics is special, usually tied to network options

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
                State.filters.minRSSI = v;
                if (this.refreshCallback) this.refreshCallback('rssi', v);
            };
        }
    },

    bindSearch() {
        const searchInput = document.getElementById('node-search');
        if (searchInput) {
            searchInput.oninput = (e) => {
                State.filters.searchQuery = e.target.value;
                if (this.refreshCallback) this.refreshCallback('search', e.target.value);
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
