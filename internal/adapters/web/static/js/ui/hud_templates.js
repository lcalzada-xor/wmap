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

        // Helper: Generate Attack Tags & Vulnerabilities
        const generateTagsObj = (n) => {
            const tags = AttackTags.getTags(n);
            if (!tags || tags.length === 0) return '';

            return `
                 <div class="sidebar-section">
                    <div class="section-title">Vulnerabilities & Tags</div>
                    <div class="quick-filter-chips" style="flex-wrap: wrap; gap: 6px;">
                        ${tags.map(t => `
                            <span class="quick-filter-btn active" style="background:${t.color}20; color:${t.color}; border-color:${t.color}40; cursor:default; font-size: 0.75em; padding: 4px 8px;">
                                ${t.label}
                            </span>
                        `).join('')}
                    </div>
                </div>`;
        };

        // Helper: Probed SSIDs
        const getProbedSSIDs = (n) => {
            if (!n.probed_ssids) return '';
            const ssids = Object.keys(n.probed_ssids);
            if (ssids.length === 0) return '';

            return `
                <div class="sidebar-section">
                    <div class="section-title">PROBED NETWORKS (PNO)</div>
                    <div class="quick-filter-chips" style="flex-wrap: wrap; gap: 6px;">
                        ${ssids.slice(0, 8).map(s => `<span class="quick-filter-btn" style="cursor:default; font-size: 0.75em; padding: 4px 8px;">${s}</span>`).join('')}
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
                <div class="sidebar-section">
                    <div class="section-title">ENCRYPTION DETAILS</div>
                    <div class="summary-row">
                        <span class="label" style="margin-left:0">Group Cipher</span>
                        <span class="value" style="font-weight:normal">${rsn.group_cipher || '-'}</span>
                    </div>
                    ${rsn.pairwise_ciphers && rsn.pairwise_ciphers.length > 0 ? `
                    <div class="summary-row">
                        <span class="label" style="margin-left:0">Pairwise</span>
                         <span class="value" style="font-weight:normal">${rsn.pairwise_ciphers.join(', ')}</span>
                    </div>` : ''}
                    ${rsn.akm_suites && rsn.akm_suites.length > 0 ? `
                    <div class="summary-row">
                        <span class="label" style="margin-left:0">Auth (AKM)</span>
                         <span class="value" style="font-weight:normal">${rsn.akm_suites.join(', ')}</span>
                    </div>` : ''}
                </div>
            `;
        };

        // Helper: WPS Extended Details
        const getWPSDetails = (n) => {
            if (!n.wps_details) return '';
            const wps = n.wps_details;

            return `
                <div class="sidebar-section">
                    <div class="section-title">WPS CONFIGURATION</div>
                    <div class="summary-row">
                         <span class="label" style="margin-left:0">State</span>
                         <span class="value" style="color: ${wps.state === 'Configured' ? Colors.WARNING : Colors.TEXT_SECONDARY}">${wps.state}</span>
                    </div>
                    ${wps.manufacturer ? `
                    <div class="summary-row">
                         <span class="label" style="margin-left:0">Manufacturer</span>
                         <span class="value" style="font-weight:normal">${wps.manufacturer}</span>
                    </div>` : ''}
                     ${wps.model ? `
                    <div class="summary-row">
                         <span class="label" style="margin-left:0">Model</span>
                         <span class="value" style="font-weight:normal">${wps.model}</span>
                    </div>` : ''}
                     ${wps.device_name ? `
                    <div class="summary-row">
                         <span class="label" style="margin-left:0">Device Name</span>
                         <span class="value" style="font-weight:normal">${wps.device_name}</span>
                    </div>` : ''}
                    ${wps.locked ? `
                    <div class="summary-row">
                         <span class="label" style="margin-left:0">Status</span>
                         <span class="value" style="color:${Colors.DANGER}">LOCKED</span>
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
                <div class="sidebar-section">
                    <div class="section-title">CONNECTION STATUS</div>
                    <div class="summary-row">
                         <span class="label" style="margin-left:0; color:${state.color}">
                            <i class="fas ${state.icon}" style="margin-right:5px;"></i> ${state.label}
                         </span>
                    </div>
                    ${n.connection_target ? `
                    <div class="summary-row">
                        <span class="label" style="margin-left:0">Target AP</span>
                        <span class="value">${n.connection_target}</span>
                    </div>` : ''}
                    ${n.connection_error ? `
                    <div class="summary-row">
                        <span class="label" style="margin-left:0">Error</span>
                        <span class="value" style="color:${Colors.DANGER}">${n.connection_error}</span>
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
                <div class="sidebar-section">
                    <div class="section-title">CAPABILITIES</div>
                    <div class="quick-filter-chips" style="flex-wrap: wrap; gap: 6px;">
                        ${caps.map(c => `
                            <span class="quick-filter-btn" style="background:${c.color}15; color:${c.color}; border-color:${c.color}30; cursor:default; font-size: 0.75em; padding: 4px 8px;">
                                ${c.label}
                            </span>
                        `).join('')}
                    </div>
                </div>
            `;
        };

        // Helper: 802.11r/k/v Protocol Support
        const getProtocolSupport = (n) => {
            const protocols = [];

            if (n.has_11k) protocols.push({ label: '802.11k', desc: 'Radio Measurement', color: '#30D158' });
            if (n.has_11v) protocols.push({ label: '802.11v', desc: 'BSS Transition', color: '#32ADE6' });
            if (n.has_11r) protocols.push({ label: '802.11r', desc: 'Fast Roaming', color: '#FFD60A' });

            if (protocols.length === 0) return '';

            return `
                <div class="sidebar-section">
                    <div class="section-title">ROAMING & MANAGEMENT</div>
                    <div style="display: flex; flex-direction: column; gap: 8px;">
                        ${protocols.map(p => `
                            <div style="display: flex; justify-content: space-between; align-items: center; padding: 6px 10px; background: ${p.color}10; border-left: 3px solid ${p.color}; border-radius: 4px;">
                                <span style="font-weight: 600; color: ${p.color}; font-size: 0.85em;">${p.label}</span>
                                <span style="font-size: 0.75em; color: var(--text-secondary);">${p.desc}</span>
                            </div>
                        `).join('')}
                    </div>
                    ${n.mobility_domain ? `
                    <div style="margin-top: 10px; padding: 8px; background: rgba(255,214,10,0.1); border-radius: 6px;">
                        <div style="font-size: 0.75em; color: var(--text-secondary); text-transform: uppercase; margin-bottom: 4px;">Mobility Domain</div>
                        <div style="font-family: var(--font-mono); font-size: 0.9em;">MDID: ${n.mobility_domain.mdid}</div>
                        ${n.mobility_domain.over_ds ? '<div style="font-size: 0.75em; color: #FFD60A; margin-top: 2px;">⚡ FT over DS Enabled</div>' : ''}
                    </div>
                    ` : ''}
                </div>
            `;
        };

        // Helper: Observed SSIDs (Karma Detection)
        const getObservedSSIDs = (n) => {
            if (!n.observed_ssids || n.observed_ssids.length <= 1) return '';

            return `
                <div class="sidebar-section">
                    <div class="section-title" style="color: var(--danger-color)">⚠️ MULTIPLE SSIDs DETECTED</div>
                    <div style="padding: 8px; background: rgba(255,69,58,0.1); border-radius: 6px; border-left: 3px solid var(--danger-color);">
                        <div style="font-size: 0.75em; color: var(--text-secondary); margin-bottom: 6px;">This AP is broadcasting multiple network names (possible Karma/Mana attack):</div>
                        <div class="quick-filter-chips" style="flex-wrap: wrap; gap: 6px;">
                            ${n.observed_ssids.map(s => `<span class="quick-filter-btn" style="background: rgba(255,69,58,0.2); color: #FF453A; border-color: #FF453A40; cursor: default; font-size: 0.75em; padding: 4px 8px;">${s}</span>`).join('')}
                        </div>
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
                <div class="sidebar-section">
                    <div class="section-title">BEHAVIORAL ANALYSIS</div>
                    ${b.anomaly_score !== undefined ? `
                    <div class="summary-row">
                        <span class="label" style="margin-left:0">Threat Level</span>
                        <span class="value" style="color:${anomalyColor}">${anomalyLabel} (${(b.anomaly_score * 100).toFixed(0)}%)</span>
                    </div>` : ''}
                    ${b.traffic_pattern ? `
                     <div class="summary-row">
                        <span class="label" style="margin-left:0">Traffic Pattern</span>
                        <span class="value" style="font-weight:normal">${b.traffic_pattern}</span>
                    </div>` : ''}
                    ${b.roaming_score !== undefined ? `
                     <div class="summary-row">
                        <span class="label" style="margin-left:0">Roaming Behavior</span>
                        <span class="value" style="font-weight:normal">${b.roaming_score > 0.7 ? 'Aggressive' : b.roaming_score > 0.3 ? 'Moderate' : 'Sticky'}</span>
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

        // Main Layout Re-structure using Sidebar Classes
        return `
            <div class="sidebar-header" style="padding-bottom: 20px; display:flex; justify-content:space-between; align-items:flex-start;">
                <div>
                    <h3 style="font-size: 1.1em; margin-bottom: 5px;">${node.label || node.mac || node.id || 'Unknown Node'}</h3>
                    <div style="font-size: 0.8em; color: var(--text-secondary); font-family: var(--font-mono);">${subHeader}</div>
                </div>
                <i class="fas fa-times" id="btn-close-details" style="cursor:pointer; opacity:0.6; font-size:1.2em; padding: 5px;"></i>
            </div>

            <div class="sidebar-section">
                <div class="summary-row">
                    <span class="label" style="margin-left: 0;">Type</span>
                    <span class="value" style="display:flex; align-items:center;">
                        <i class="fas ${detailIcon}" style="margin-right:8px; color: ${detailColor}"></i> ${type}
                    </span>
                </div>
                <div class="summary-row">
                    <span class="label" style="margin-left: 0;">Vendor</span>
                    <span class="value" style="font-weight: normal; text-align: right;">${vendor}</span>
                </div>
                <div class="summary-row">
                    <span class="label" style="margin-left: 0;">Network</span>
                    <span class="value">${ssid}</span>
                </div>
                 <div class="summary-row">
                    <span class="label" style="margin-left: 0;">Security</span>
                    <span class="value">
                        ${security === 'OPEN' ? '<span style="color:var(--danger-color)">OPEN</span>' : `<span style="color:var(--accent-color)">${security}</span>`}
                    </span>
                </div>
            </div>

            <div class="sidebar-section">
                <div class="section-title">SIGNAL QUALITY (${rssiVal} dBm)</div>
                <div class="signal-bar-container" style="margin-top: 8px;">
                    <div class="signal-bar" style="width:${signalWidth}; background:${signalColor};"></div>
                </div>
                 <div style="display: flex; gap: 10px; margin-top: 10px;">
                    <div style="flex:1; background: rgba(255,255,255,0.05); padding: 8px; border-radius: 8px;">
                        <div style="font-size: 0.7em; color: var(--text-secondary); text-transform: uppercase;">Channel</div>
                        <div style="font-weight: bold; margin-top: 2px;">${channel}</div>
                    </div>
                     <div style="flex:1; background: rgba(255,255,255,0.05); padding: 8px; border-radius: 8px;">
                        <div style="font-size: 0.7em; color: var(--text-secondary); text-transform: uppercase;">Frequency</div>
                        <div style="font-weight: bold; margin-top: 2px;">${freq}</div>
                    </div>
                </div>
            </div>

            ${getConnectionState(node)}
            ${generateTagsObj(node)}
            ${getObservedSSIDs(node)}
            ${getCapabilities(node)}
            ${getProtocolSupport(node)}
            ${getSecurityDetails(node)}
            ${getWPSDetails(node)}
            ${getProbedSSIDs(node)}
            ${getBehavioralAnalysis(node)}

            <div class="sidebar-section">
                <div class="section-title">TRAFFIC STATS</div>
                 <div class="summary-row">
                     <span class="label" style="margin-left:0">TX Data</span>
                     <span class="value">${tx}</span>
                </div>
                 <div class="summary-row">
                     <span class="label" style="margin-left:0">RX Data</span>
                     <span class="value">${rx}</span>
                </div>
                 <div class="summary-row">
                     <span class="label" style="margin-left:0">Packets</span>
                     <span class="value">${packets}</span>
                </div>
            </div>

             <div class="sidebar-section">
                <div class="section-title">ACTIVITY LOG</div>
                 <div class="summary-row">
                     <span class="label" style="margin-left:0">First Seen</span>
                     <span class="value" style="font-weight:normal; font-size: 0.9em;">${seenFirst}</span>
                </div>
                 <div class="summary-row">
                     <span class="label" style="margin-left:0">Last Seen</span>
                     <span class="value" style="font-weight:normal; font-size: 0.9em;">${seenLast}</span>
                </div>
            </div>

            ${node.hasHandshake ? `
            <div class="sidebar-section">
                <div class="section-title" style="color:var(--success-color)">HANDSHAKE CAPTURED</div>
                <button class="action-btn-secondary" style="width:100%; font-size:0.9em; margin-top: 5px;" data-action="open-handshakes">
                    <i class="fas fa-folder-open"></i> Open Captures Folder
                </button>
            </div>
            ` : ''}

            ${(node.wps_info && !node.wps_details) || node.wps_details ? `
            <div class="sidebar-section">
                <div class="section-title" style="color:var(--warning-color)">WPS ATTACK VECTOR</div>
                 <button class="action-btn-secondary" style="width:100%; font-size:0.9em; border-color: var(--warning-color); color: var(--warning-color); margin-top: 5px;" 
                    data-action="wps-attack" data-mac="${node.mac}" data-channel="${node.channel || 0}">
                    <i class="fas fa-magic"></i> Start Pixie Dust Attack
                </button>
            </div>
            ` : ''}

            <div class="sidebar-section">
                <button class="action-btn-secondary" style="width:100%; font-size:0.9em" data-action="copy-id" data-text="${node.mac || node.id}">
                    <i class="far fa-copy"></i> Copy MAC Address
                </button>
            </div>
        `;
    }
};
