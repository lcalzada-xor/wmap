/**
 * HUD Controller
 * Manages sidebar controls and event listeners.
 */

import { State } from '../core/state.js';
import { API } from '../core/api.js';
import { Notifications } from './notifications.js';
import { NodeGroups, Colors } from '../core/constants.js';
import { HUDTemplates } from './hud_templates.js';

export const HUD = {
    init(refreshCallback) {
        this.refreshCallback = refreshCallback;
        this.bindToggles();
        this.bindSearch();
        this.bindActionButtons();
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
                    fetch(`/api/config/persistence?enabled=${val}`, { method: 'POST' });
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
        const btnClear = document.getElementById('btn-clear-session');
        if (btnClear) {
            btnClear.onclick = () => {
                if (confirm("Clear all session data? This cannot be undone.")) {
                    API.clearSession().then(() => {
                        Notifications.show("Session Cleared", "success");
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
            formatBytes: this.formatBytes,
            timeAgo: this.timeAgo
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
    },

    formatBytes(bytes, decimals = 2) {
        if (!+bytes) return '0 B';
        const k = 1024;
        const dm = decimals < 0 ? 0 : decimals;
        const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return `${parseFloat((bytes / Math.pow(k, i)).toFixed(dm))} ${sizes[i]}`;
    },

    timeAgo(dateString) {
        if (!dateString || dateString.startsWith('0001-01-01')) return 'Never';
        const date = new Date(dateString);
        if (isNaN(date.getTime())) return 'Unknown';

        const seconds = Math.floor((new Date() - date) / 1000);
        if (seconds < 60) return "Just now";

        let interval = seconds / 31536000;
        if (interval > 1) return Math.floor(interval) + " years ago";
        interval = seconds / 2592000;
        if (interval > 1) return Math.floor(interval) + " months ago";
        interval = seconds / 86400;
        if (interval > 1) return Math.floor(interval) + " days ago";
        interval = seconds / 3600;
        if (interval > 1) return Math.floor(interval) + " hours ago";
        interval = seconds / 60;
        if (interval > 1) return Math.floor(interval) + " mins ago";

        return Math.floor(seconds) + " seconds ago";
    }
};
