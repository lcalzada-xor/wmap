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

        // Helper: Generate Attack Tags
        const generateTagsObj = (n) => {
            const tags = AttackTags.getTags(n);
            if (!tags || tags.length === 0) return '';

            return `
                <div class="attack-tags-container">
                    ${tags.map(t => `
                        <span class="attack-tag" style="background:${t.color}20; color:${t.color}; border-color:${t.color}40;">
                            ${t.label}
                        </span>
                    `).join('')}
                </div>`;
        };

        // Helper: Probed SSIDs
        const getProbedSSIDs = (n) => {
            if (!n.probed_ssids) return '';
            const ssids = Object.keys(n.probed_ssids);
            if (ssids.length === 0) return '';

            return `
                <div class="detail-section">
                    <div class="section-header">PROBED NETWORKS (PNO)</div>
                    <div style="display:flex; flex-wrap:wrap; gap:5px;">
                        ${ssids.slice(0, 8).map(s => `<span class="attack-tag" style="background:rgba(255,255,255,0.05); border:1px solid rgba(255,255,255,0.1); font-weight:normal;">${s}</span>`).join('')}
                        ${ssids.length > 8 ? `<span style="font-size:0.8em; opacity:0.6; align-self:center;">+${ssids.length - 8} more</span>` : ''}
                    </div>
                </div>
             `;
        };

        // Helper: Security Details (RSN)
        const getSecurityDetails = (n) => {
            if (!n.rsn_info) return '';
            const rsn = n.rsn_info;

            return `
                <div class="detail-section">
                    <div class="section-header">ENCRYPTION DETAILS</div>
                    <div class="detail-row flex-between">
                        <div class="detail-label">Group Cipher</div>
                        <div class="detail-value">${rsn.group_cipher || '-'}</div>
                    </div>
                    ${rsn.pairwise_ciphers && rsn.pairwise_ciphers.length > 0 ? `
                    <div class="detail-row flex-between">
                        <div class="detail-label">Pairwise</div>
                        <div class="detail-value">${rsn.pairwise_ciphers.join(', ')}</div>
                    </div>` : ''}
                    ${rsn.akm_suites && rsn.akm_suites.length > 0 ? `
                    <div class="detail-row flex-between">
                        <div class="detail-label">Auth (AKM)</div>
                        <div class="detail-value">${rsn.akm_suites.join(', ')}</div>
                    </div>` : ''}
                </div>
            `;
        };

        // Helper: WPS Extended Details
        const getWPSDetails = (n) => {
            if (!n.wps_details) return '';
            const wps = n.wps_details;

            return `
                <div class="detail-section">
                    <div class="section-header">WPS CONFIGURATION</div>
                    <div class="detail-row flex-between">
                        <div class="detail-label">State</div>
                        <div class="detail-value" style="color: ${wps.state === 'Configured' ? Colors.WARNING : Colors.TEXT_SECONDARY}">${wps.state}</div>
                    </div>
                    ${wps.manufacturer ? `
                    <div class="detail-row flex-between">
                        <div class="detail-label">Manufacturer</div>
                        <div class="detail-value">${wps.manufacturer}</div>
                    </div>` : ''}
                     ${wps.model ? `
                    <div class="detail-row flex-between">
                        <div class="detail-label">Model</div>
                        <div class="detail-value">${wps.model}</div>
                    </div>` : ''}
                     ${wps.device_name ? `
                    <div class="detail-row flex-between">
                        <div class="detail-label">Device Name</div>
                        <div class="detail-value">${wps.device_name}</div>
                    </div>` : ''}
                    ${wps.locked ? `
                    <div class="detail-row flex-between">
                        <div class="detail-label">Status</div>
                        <div class="detail-value" style="color:${Colors.DANGER}">LOCKED</div>
                    </div>` : ''}
                </div>
            `;
        };

        // Helper: Connection State
        const getConnectionState = (n) => {
            if (!n.connection_state || n.group === NodeGroups.AP) return '';

            const stateMap = {
                'disconnected': { color: Colors.TEXT_SECONDARY, icon: 'fa-times-circle', label: 'Disconnected' },
                'authenticating': { color: Colors.WARNING, icon: 'fa-spinner', label: 'Authenticating' },
                'associating': { color: Colors.WARNING, icon: 'fa-link', label: 'Associating' },
                'handshake': { color: '#FFD60A', icon: 'fa-key', label: 'Handshake' },
                'connected': { color: Colors.SUCCESS, icon: 'fa-check-circle', label: 'Connected' }
            };

            const state = stateMap[n.connection_state] || { color: Colors.TEXT_SECONDARY, icon: 'fa-question', label: n.connection_state };

            return `
                <div class="detail-section">
                    <div class="section-header">CONNECTION STATUS</div>
                    <div class="detail-row flex-between">
                        <div class="detail-label">
                            <i class="fas ${state.icon}" style="color: ${state.color}; margin-right:5px;"></i>
                            ${state.label}
                        </div>
                    </div>
                    ${n.connection_target ? `
                    <div class="detail-row flex-between">
                        <div class="detail-label">Target AP</div>
                        <div class="detail-value" style="font-size:0.85em;">${n.connection_target}</div>
                    </div>` : ''}
                    ${n.connection_error ? `
                    <div class="detail-row flex-between">
                        <div class="detail-label">Error</div>
                        <div class="detail-value" style="color:${Colors.DANGER};">${n.connection_error}</div>
                    </div>` : ''}
                </div>
            `;
        };

        // Helper: WiFi Capabilities
        const getCapabilities = (n) => {
            const caps = [];

            if (n.is_wifi7) caps.push({ label: 'WiFi 7 (BE)', color: '#BF5AF2' });
            else if (n.is_wifi6) caps.push({ label: 'WiFi 6 (AX)', color: '#64D2FF' });

            if (n.capabilities && n.capabilities.length > 0) {
                n.capabilities.forEach(c => {
                    if (c === 'HT' || c === 'HT40') caps.push({ label: c, color: '#86868B' });
                    else if (c === 'VHT') caps.push({ label: c, color: '#86868B' });
                    else if (c === 'WMM') caps.push({ label: c, color: '#30D158' });
                    else caps.push({ label: c, color: '#86868B' });
                });
            }

            if (caps.length === 0) return '';

            return `
                <div class="detail-section">
                    <div class="section-header">CAPABILITIES</div>
                    <div style="display:flex; flex-wrap:wrap; gap:5px;">
                        ${caps.map(c => `<span class="attack-tag" style="background:${c.color}20; color:${c.color}; border-color:${c.color}40;">${c.label}</span>`).join('')}
                    </div>
                </div>
            `;
        };

        // Helper: Behavioral Analysis
        const getBehavioralAnalysis = (n) => {
            if (!n.behavioral) return '';
            const b = n.behavioral;

            let anomalyColor = Colors.SUCCESS;
            let anomalyLabel = 'Normal';
            if (b.anomaly_score > 0.7) { anomalyColor = Colors.DANGER; anomalyLabel = 'High Risk'; }
            else if (b.anomaly_score > 0.4) { anomalyColor = Colors.WARNING; anomalyLabel = 'Suspicious'; }

            return `
                <div class="detail-section">
                    <div class="section-header">BEHAVIORAL ANALYSIS</div>
                    ${b.anomaly_score !== undefined ? `
                    <div class="detail-row flex-between">
                        <div class="detail-label">Threat Level</div>
                        <div class="detail-value" style="color:${anomalyColor};">${anomalyLabel} (${(b.anomaly_score * 100).toFixed(0)}%)</div>
                    </div>` : ''}
                    ${b.traffic_pattern ? `
                    <div class="detail-row flex-between">
                        <div class="detail-label">Traffic Pattern</div>
                        <div class="detail-value">${b.traffic_pattern}</div>
                    </div>` : ''}
                    ${b.roaming_score !== undefined ? `
                    <div class="detail-row flex-between">
                        <div class="detail-label">Roaming Behavior</div>
                        <div class="detail-value">${b.roaming_score > 0.7 ? 'Aggressive' : b.roaming_score > 0.3 ? 'Moderate' : 'Sticky'}</div>
                    </div>` : ''}
                </div>
            `;
        };

        let vendor = node.vendor || 'Unknown';
        if (node.model) vendor += ` <span style="opacity:0.6; font-size:0.9em;">(${node.model})</span>`;
        if (node.os) vendor += ` <div style="font-size:0.8em; color:var(--accent-color); margin-top:2px;">${node.os}</div>`;

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
                <div class="detail-header">${node.label || node.mac || node.id || 'Unknown Node'}</div>
                <div class="detail-subheader">${subHeader}</div>
                ${generateTagsObj(node)}
             </div>

            <div class="detail-row">
                <div class="detail-label">Type</div>
                <div class="detail-value" style="display:flex; align-items:center;">
                   <i class="fas ${detailIcon}" style="margin-right:8px; color: ${detailColor}"></i>
                   ${type}
                </div>
            </div>

            <div class="detail-row">
                <div class="detail-label">Vendor / Device</div>
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
                   ${security === 'OPEN' ? '<span style="color:var(--danger-color)">OPEN</span>' : `<span style="color:var(--accent-color)">${security}</span>`}
                </div>
            </div>

            <div class="detail-row">
                <div class="detail-label">Signal Quality (${rssiVal} dBm)</div>
                <div class="signal-bar-container">
                    <div class="signal-bar" style="width:${signalWidth}; background:${signalColor};"></div>
                </div>
            </div>

            <div class="stats-grid">
                 <div class="detail-row" style="margin:0;">
                    <div class="detail-label">Channel</div>
                    <div class="detail-value">${channel}</div>
                </div>
                 <div class="detail-row" style="margin:0;">
                    <div class="detail-label">Frequency</div>
                    <div class="detail-value">${freq}</div>
                </div>
            </div>

            ${getConnectionState(node)}
            ${getCapabilities(node)}
            ${getSecurityDetails(node)}
            ${getWPSDetails(node)}
            ${getProbedSSIDs(node)}
            ${getBehavioralAnalysis(node)}

            <div class="detail-section">
                <div class="section-header">TRAFFIC STATS</div>
                 <div class="detail-row flex-between">
                    <div class="detail-label">Data Transmitted</div>
                    <div class="detail-value">${tx}</div>
                </div>
                 <div class="detail-row flex-between">
                    <div class="detail-label">Data Received</div>
                    <div class="detail-value">${rx}</div>
                </div>
                 <div class="detail-row flex-between">
                    <div class="detail-label">Total Packets</div>
                    <div class="detail-value">${packets}</div>
                </div>
            </div>

            <div class="detail-section">
                <div class="section-header">ACTIVITY</div>
                 <div class="detail-row flex-between">
                    <div class="detail-label">First Seen</div>
                    <div class="detail-value">${seenFirst}</div>
                </div>
                 <div class="detail-row flex-between">
                    <div class="detail-label">Last Seen</div>
                    <div class="detail-value">${seenLast}</div>
                </div>
            </div>

            ${node.hasHandshake ? `
            <div class="detail-section">
                <div class="section-header">HANDSHAKE CAPTURED</div>
                <div class="detail-row flex-between">
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

            ${node.wps_info && !node.wps_details ? `
            <div class="detail-section">
                <div class="section-header">WPS DETECTED</div>
                <div class="detail-row flex-between">
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

            ${node.wps_details ? `
                <div style="margin-top:10px;">
                    <button class="action-btn-secondary" style="width:100%; font-size:0.9em; border-color: var(--warning-color); color: var(--warning-color);" 
                        data-action="wps-attack" data-mac="${node.mac}" data-channel="${node.channel || 0}">
                        <i class="fas fa-magic"></i> Start Pixie Dust Attack
                    </button>
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
