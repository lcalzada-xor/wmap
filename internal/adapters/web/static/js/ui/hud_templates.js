import { NodeGroups, Colors } from '../core/constants.js';
import { AttackTags } from '../core/attack_tags.js';

/**
 * HTML Templates for HUD components
 * Separates markup from logic.
 */
export const HUDTemplates = {
    /**
     * Generates the HTML for node details
     * @param {Object} node - The node data object
     * @param {Object} formatters - Helper functions like formatBytes, timeAgo
     * @returns {string} HTML string
     */
    detailsPanel: (node, formatters) => {
        let type = 'Station';
        let detailIcon = 'fa-mobile-alt';
        let detailColor = Colors.DANGER;

        if (node.group === NodeGroups.AP) {
            type = 'Access Point';
            detailIcon = 'fa-wifi';
            detailColor = Colors.NODE_AP;
        } else if (node.group === NodeGroups.NETWORK) {
            type = 'SSID Network';
            detailIcon = 'fa-cloud';
            detailColor = Colors.NODE_NETWORK;
        }

        // Generate Attack Tags
        const tags = AttackTags.getTags(node);
        let tagsHtml = '';
        if (tags.length > 0) {
            tagsHtml = `<div class="attack-tags-container">`;
            tagsHtml += tags.map(t => `<span class="attack-tag" style="background:${t.color}20; color:${t.color}; border-color:${t.color}40;">${t.label}</span>`).join('');
            tagsHtml += `</div>`;
        }

        const vendor = node.vendor || 'Unknown';
        const ssid = node.ssid || '<span style="opacity:0.5">N/A</span>';
        const channel = node.channel ? node.channel : '<span style="opacity:0.5">N/A</span>';
        const rssiVal = node.rssi !== undefined ? node.rssi : -100;

        // Signal Logic
        let signalColor = Colors.DANGER;
        let signalWidth = '20%';
        if (rssiVal > -50) { signalColor = Colors.SIGNAL_STRONG; signalWidth = '100%'; }
        else if (rssiVal > -70) { signalColor = Colors.SIGNAL_GOOD; signalWidth = '70%'; }
        else if (rssiVal > -85) { signalColor = Colors.SIGNAL_WEAK; signalWidth = '40%'; }

        const freqVal = node.frequency || node.freq;
        const freq = freqVal ? `${(freqVal / 1000).toFixed(1)} GHz` : 'N/A';
        const security = node.security || (node.group === NodeGroups.NETWORK ? 'Unknown' : 'OPEN');

        const tx = formatters.formatBytes(node.data_tx || 0);
        const rx = formatters.formatBytes(node.data_rx || 0);
        const packets = node.packets || 0;

        const seenFirst = formatters.timeAgo(node.first_seen);
        const seenLast = formatters.timeAgo(node.last_seen);
        const subHeader = node.mac || node.id || '';

        return `
            <div class="detail-row" style="border:none; margin-bottom:20px;">
                <div style="font-size:1.2em; font-weight:700; margin-bottom:5px;">${node.label || node.mac || node.id}</div>
                <div style="font-size:0.9em; opacity:0.7;">${subHeader}</div>
                ${tagsHtml}
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

            ${node.hasHandshake ? `
            <div style="margin-top:15px; padding-top:15px; border-top:1px solid var(--panel-border);">
                <div style="font-size:0.8em; color:var(--text-secondary); margin-bottom:10px; font-weight:600; letter-spacing:1px;">HANDSHAKE CAPTURED</div>
                <div class="detail-row" style="justify-content:space-between">
                    <div class="detail-label">
                        <i class="fas fa-check-circle" style="color: var(--success-color); margin-right:5px;"></i>
                        WPA Handshake Available
                    </div>
                </div>
                <div style="margin-top:10px;">
                    <button class="action-btn-secondary" style="width:100%; font-size:0.9em" data-action="open-handshakes">
                        <i class="fas fa-folder-open"></i> Open Captures Folder
                    </button>
                </div>
            </div>
            ` : ''}

            ${node.wps_info ? `
            <div style="margin-top:15px; padding-top:15px; border-top:1px solid var(--panel-border);">
                <div style="font-size:0.8em; color:var(--text-secondary); margin-bottom:10px; font-weight:600; letter-spacing:1px;">WPS DETECTED</div>
                <div class="detail-row" style="justify-content:space-between">
                    <div class="detail-label">
                        <i class="fas fa-lock-open" style="color: var(--warning-color); margin-right:5px;"></i>
                        ${node.wps_info}
                    </div>
                </div>
                <div style="margin-top:10px;">
                    <button class="action-btn-secondary" style="width:100%; font-size:0.9em; border-color: var(--warning-color); color: var(--warning-color);" 
                        data-action="wps-attack" data-mac="${node.mac}" data-channel="${node.channel || 0}">
                        <i class="fas fa-magic"></i> Start Pixie Dust Attack
                    </button>
                </div>
            </div>
            ` : ''}

            <div style="margin-top:20px;">
                <button class="action-btn-secondary" style="width:100%; font-size:0.9em" data-action="copy-id" data-text="${node.mac || node.id}">
                    <i class="far fa-copy"></i> Copy ID
                </button>
            </div>
        `;
    }
};
