/**
 * HUD Controller
 * Manages sidebar controls and event listeners.
 */

import { State } from '../core/state.js';
import { API } from '../core/api.js';
import { Notifications } from './notifications.js';

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

        // Data Prep
        // Fix: Detect group properly to avoid "Station" default for Networks
        let type = 'Station';
        let detailIcon = 'fa-mobile-alt';
        let detailColor = '#ff453a';

        if (node.group === 'ap') {
            type = 'Access Point';
            detailIcon = 'fa-wifi';
            detailColor = '#30d158';
        } else if (node.group === 'network') {
            type = 'SSID Network';
            detailIcon = 'fa-cloud';
            detailColor = '#0a84ff';
        }

        const vendor = node.vendor || 'Unknown';
        const ssid = node.ssid || '<span style="opacity:0.5">N/A</span>';
        const channel = node.channel ? node.channel : '<span style="opacity:0.5">N/A</span>';
        const rssiVal = node.rssi !== undefined ? node.rssi : -100;

        // New Data
        // Fix: JSON uses 'frequency', JS was using 'freq'
        const freqVal = node.frequency || node.freq;
        const freq = freqVal ? `${(freqVal / 1000).toFixed(1)} GHz` : 'N/A';
        const width = node.bw ? `${node.bw} MHz` : 'N/A';
        const security = node.security || (node.group === 'network' ? 'Unknown' : 'OPEN');

        // Traffic
        const tx = this.formatBytes(node.data_tx || 0);
        const rx = this.formatBytes(node.data_rx || 0);
        const packets = node.packets || 0;

        // Time
        const seenFirst = this.timeAgo(node.first_seen);
        const seenLast = this.timeAgo(node.last_seen);

        // Subheader (MAC or ID)
        const subHeader = node.mac || node.id || '';

        // Signal Bar Logic
        let signalColor = '#ff453a';
        let signalWidth = '20%';
        if (rssiVal > -50) { signalColor = '#30d158'; signalWidth = '100%'; }
        else if (rssiVal > -70) { signalColor = '#ffcf00'; signalWidth = '70%'; }
        else if (rssiVal > -85) { signalColor = '#ff9f0a'; signalWidth = '40%'; }

        // Template
        content.innerHTML = `
            <div class="detail-row" style="border:none; margin-bottom:20px;">
                <div style="font-size:1.2em; font-weight:700; margin-bottom:5px;">${node.label || node.mac || node.id}</div>
                <div style="font-size:0.9em; opacity:0.7;">${subHeader}</div>
             </div>

            <div class="detail-row">
                <div class="detail-label">Type</div>
                <div class="detail-value" style="display:flex; align-items:center;">
                   <i class="fas ${detailIcon}" style="margin-right:8px; color: ${detailColor}"></i>
                   ${type}
                </div>
            </div>

            <div class="detail-row">
                <div class="detail-label">Vendor</div>
                <div class="detail-value">${vendor}</div>
            </div>

             <div class="detail-row">
                <div class="detail-label">Network</div>
                <div class="detail-value">
                   SSID: <strong>${ssid}</strong>
                </div>
            </div>

             <div class="detail-row">
                <div class="detail-label">Security</div>
                <div class="detail-value">
                   <span style="color:var(--accent-color)">${security}</span>
                </div>
            </div>

            <div class="detail-row">
                <div class="detail-label">Signal Quality (${rssiVal} dBm)</div>
                <div style="width:100%; height:8px; background:rgba(255,255,255,0.1); border-radius:4px; margin-top:5px; overflow:hidden;">
                    <div style="width:${signalWidth}; height:100%; background:${signalColor}; transition:width 0.3s ease;"></div>
                </div>
            </div>

            <div style="display:grid; grid-template-columns: 1fr 1fr; gap:10px; margin-top:10px;">
                 <div class="detail-row" style="margin:0;">
                    <div class="detail-label">Channel</div>
                    <div class="detail-value">${channel}</div>
                </div>
                 <div class="detail-row" style="margin:0;">
                    <div class="detail-label">Frequency</div>
                    <div class="detail-value">${freq}</div>
                </div>
            </div>

            <div style="margin-top:15px; padding-top:15px; border-top:1px solid var(--panel-border);">
                <div style="font-size:0.8em; color:var(--text-secondary); margin-bottom:10px; font-weight:600; letter-spacing:1px;">TRAFFIC STATS</div>
                 <div class="detail-row" style="justify-content:space-between">
                    <div class="detail-label">Data Transmitted</div>
                    <div class="detail-value">${tx}</div>
                </div>
                 <div class="detail-row" style="justify-content:space-between">
                    <div class="detail-label">Data Received</div>
                    <div class="detail-value">${rx}</div>
                </div>
                 <div class="detail-row" style="justify-content:space-between">
                    <div class="detail-label">Total Packets</div>
                    <div class="detail-value">${packets}</div>
                </div>
            </div>

            <div style="margin-top:15px; padding-top:15px; border-top:1px solid var(--panel-border);">
                <div style="font-size:0.8em; color:var(--text-secondary); margin-bottom:10px; font-weight:600; letter-spacing:1px;">ACTIVITY</div>
                 <div class="detail-row" style="justify-content:space-between">
                    <div class="detail-label">First Seen</div>
                    <div class="detail-value">${seenFirst}</div>
                </div>
                 <div class="detail-row" style="justify-content:space-between">
                    <div class="detail-label">Last Seen</div>
                    <div class="detail-value">${seenLast}</div>
                </div>
            </div>

            <div style="margin-top:20px;">
                <button class="action-btn-secondary" style="width:100%; font-size:0.9em" onclick="HUD.copyToClipboard('${node.mac || node.id}')">
                    <i class="far fa-copy"></i> Copy ID
                </button>
            </div>
        `;

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
