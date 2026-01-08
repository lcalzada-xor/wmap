/**
 * Attack Tags Generation
 * Maps security protocols and device states to potential attack vectors.
 */

export const AttackTags = {
    /**
     * Analyzes node properties to determine potential attack vectors.
     * @param {Object} node - The node data object
     * @returns {Array} Array of tag objects { label, color, desc }
     */
    getTags(node) {
        const tags = [];

        // Safety check
        if (!node) return tags;

        const security = (node.security || '').toUpperCase();
        const wps = (node.wps_info || '').toLowerCase();
        const capabilities = node.capabilities || [];

        // 1. WEP (The weakest)
        if (security.includes('WEP')) {
            tags.push({ label: 'WEP', color: '#ff3b30', desc: 'Aircrack-ng / IVs' }); // Red
        }

        // 2. WPS (Pixie Dust / Brute Force)
        // Check if explicitly configured/unconfigured OR just has WPS cap
        if (wps.includes('configured') || capabilities.includes('WPS')) {
            tags.push({ label: 'WPS', color: '#ff9500', desc: 'Pixie Dust / Reaver' }); // Orange
        }

        // 3. WPA2 + KRACK
        // WPA2 is generally secure-ish but vulnerable to KRACK
        if (security.includes('WPA2')) {
            tags.push({ label: 'KRACK', color: '#ffcc00', desc: 'Key Reinstallation' }); // Yellow
        }

        // 4. OPEN (No Encryption)
        if (security === 'OPEN' || security === '' || security === 'NONE') {
            tags.push({ label: 'UNSECURE', color: '#ff3b30', desc: 'No Encryption' }); // Red
        }

        // 5. WPA3 (Dragonblood - specific conditions, but broadly relevant for research)
        if (security.includes('WPA3')) {
            tags.push({ label: 'DRAGON', color: '#007aff', desc: 'Dragonblood / Downgrade' }); // Blue
        }

        return tags;
    },

    /**
     * Formats the node label to include attack tags.
     * @param {String} originalLabel - The current label of the node
     * @param {Array} tags - Array of tag objects from getTags
     * @returns {String} Formatted label
     */
    formatLabel(originalLabel, tags) {
        if (!tags || tags.length === 0) return originalLabel;

        // Create a string of tags: [WEP] [WPS]
        const tagString = tags.map(t => `[${t.label}]`).join(' ');

        // Return with newline so tags appear above or below the name
        // Placing below the name for better readability of the ESSID
        return `${originalLabel}\n${tagString}`;
    }
};
