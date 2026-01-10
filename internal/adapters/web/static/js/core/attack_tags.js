/**
 * Attack Tags Generation
 * Maps security protocols and device states to potential attack vectors.
 */

export const AttackTags = {
    /**
     * Analyzes node properties to determine potential attack vectors.
     * @param {Object} node - The node data object
     * @returns {Array} Array of tag objects { label, color, desc, confidence, severity }
     */
    getTags(node) {
        let tags = [];

        // Safety check
        if (!node) return tags;

        // 1. Prefer vulnerabilities from the backend (Passive Intelligence)
        if (node.vulnerabilities && node.vulnerabilities.length > 0) {
            tags = node.vulnerabilities.map(v => {
                const confChar = v.confidence >= 0.8 ? '' : '?';
                return {
                    label: `${v.name}${confChar}`,
                    color: this.getSeverityColor(v.severity),
                    desc: v.description,
                    confidence: v.confidence,
                    severity: v.severity,
                    backend: true
                };
            });
        }

        const security = (node.security || '').toUpperCase();
        const wps = (node.wps_info || '').toLowerCase();
        const capabilities = node.capabilities || [];

        const addTag = (tag) => {
            if (!tags.some(t => t.label.startsWith(tag.label))) {
                tags.push(tag);
            }
        };

        // 2. WEP (The weakest)
        if (security.includes('WEP')) {
            addTag({ label: 'WEP', color: '#ff3b30', desc: 'Aircrack-ng / IVs', severity: 10 });
        }

        // 3. WPS (Pixie Dust / Brute Force)
        if (wps.includes('configured') || capabilities.includes('WPS') || node.wps_info) {
            addTag({ label: 'WPS', color: '#ff9500', desc: 'Pixie Dust / Reaver', severity: 7 });
        }

        // 4. OPEN (No Encryption)
        if (security === 'OPEN' || security === '' || security === 'NONE') {
            addTag({ label: 'UNSECURE', color: '#ff3b30', desc: 'No Encryption', severity: 10 });
        }

        // 5. WPA3 (Dragonblood)
        if (security.includes('WPA3')) {
            addTag({ label: 'WPA3', color: '#007aff', desc: 'Dragonblood / Downgrade', severity: 2 });
        }

        // Sort tags by severity (highest first)
        return tags.sort((a, b) => (b.severity || 0) - (a.severity || 0));
    },

    /**
     * Maps severity score to color
     */
    getSeverityColor(severity) {
        if (severity >= 9) return '#ff3b30'; // Critical (Red)
        if (severity >= 7) return '#ff9500'; // High (Orange)
        if (severity >= 5) return '#ffcc00'; // Medium (Yellow)
        if (severity >= 3) return '#34c759'; // Low (Green)
        return '#007aff'; // Info (Blue)
    },

    /**
     * Formats the node label to include attack tags.
     * @param {String} originalLabel - The current label of the node
     * @param {Array} tags - Array of tag objects from getTags
     * @returns {String} Formatted label
     */
    formatLabel(originalLabel, tags) {
        if (!tags || tags.length === 0) return originalLabel;

        // Take top 3 tags to avoid clutter
        const displayTags = tags.slice(0, 3);
        const tagString = displayTags.map(t => `[${t.label}]`).join(' ');

        return `${originalLabel}\n${tagString}`;
    }
};
