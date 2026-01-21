import { Utils } from '../core/utils.js';

export const DeauthTemplates = {
    /**
     * Render an attack list item
     * @param {Object} attack 
     * @returns {string} HTML string
     */
    attackItem(attack) {
        // Calculate duration logic
        let durationStr = '0s';
        if (attack.end_time) {
            durationStr = Utils.timeAgo(attack.start_time); // Use timeAgo logic or custom duration?
            // Actually, deauth item showed "Xm Ys", Utils.timeAgo shows "X mins ago".
            // Let's copy the duration formatting logic or rely on Utils if acceptable.
            // The original used a custom formatDuration(ms). Let's keep it consistent by moving that logic here or to Utils.
            // For now, let's assume we want the same "Xh Ym" format.
            // It's specific to duration, not "time ago".
            // Let's add formatDuration to this template or use a local helper.
        } else {
            // Live duration
            // Logic was: Date.now() - start_time
        }

        // We defer the dynamic duration calculation to the render loop or do it here if passed value.
        // The original passed milliseconds to formatDuration.
        // Let's assume the caller passes the formatted duration string or we do it here.
        // Better: Caller passes ready-to-display duration string.
    },

    // Better approach: Replicate renderAttackItem logic but just the HTML structure.
    renderAttackItem(attack, formattedDuration) {
        const statusClass = attack.status.toLowerCase();
        const interfaceInfo = attack.config.interface ? `<br><strong>Interface:</strong> ${attack.config.interface}` : '';
        const handshakeBadge = attack.handshake_captured
            ? `<span style="background:var(--success-color); color:black; padding:2px 6px; border-radius:4px; font-size:0.8em; font-weight:bold; margin-left:5px;"><i class="fas fa-key"></i> PWNED</span>`
            : '';

        return `
            <div class="attack-item">
                <div class="attack-header">
                    <span class="attack-id">${attack.id.substring(0, 8)}...</span>
                    <span>
                        ${handshakeBadge}
                        <span class="attack-status ${statusClass}">${attack.status}</span>
                    </span>
                </div>
                <div style="font-size: 0.85em; margin: 6px 0;">
                    <strong>Target:</strong> ${attack.config.target_mac}<br>
                    <strong>Type:</strong> ${attack.config.attack_type}${interfaceInfo}
                </div>
                <div class="attack-metrics">
                    <span><i class="fas fa-paper-plane"></i> ${attack.packets_sent} packets</span>
                    <span><i class="fas fa-clock"></i> ${formattedDuration}</span>
                </div>
                ${attack.status === 'running' ? `
                    <div class="attack-controls">
                        <button class="btn-stop btn-stop-attack" data-attack-id="${attack.id}">
                            <i class="fas fa-stop"></i> Stop
                        </button>
                        <button class="btn-stop btn-force-stop-attack" data-attack-id="${attack.id}" style="background: var(--danger-color); margin-left: 5px;">
                            <i class="fas fa-skull"></i> Force
                        </button>
                    </div>
                ` : ''}
            </div>
        `;
    },

    emptyList() {
        return `
            <div style="text-align: center; opacity: 0.6; padding: 20px; font-size: 0.85em;">
                No active attacks
            </div>
        `;
    }
};
