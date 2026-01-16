/**
 * Graph Styler
 * Encapsulates visual logic for Nodes and Edges.
 */

import { State } from '../core/state.js';
import { NodeGroups } from '../core/constants.js';

export const GraphStyler = {
    styleNode(n) {
        // Notifications & Aliases
        if (State.getAlias(n.mac)) {
            n.label = State.getAlias(n.mac);
            n.font = { color: '#FFD60A' };
        }

        // WiFi Generation Styling - System Colors
        if (n.is_wifi7) {
            n.borderWidth = 2;
            n.color = {
                border: '#BF5AF2', // System Purple
                background: 'rgba(191, 90, 242, 0.2)'
            };
            n.shadow = { color: 'rgba(191, 90, 242, 0.4)', size: 10, x: 0, y: 0 };
        } else if (n.is_wifi6) {
            n.borderWidth = 2;
            n.color = {
                border: '#64D2FF', // System Cyan
                background: 'rgba(100, 210, 255, 0.2)'
            };
            n.shadow = { color: 'rgba(100, 210, 255, 0.4)', size: 8, x: 0, y: 0 };
        }

        // Randomized MAC - Subtle Glass
        if (n.is_randomized) {
            n.opacity = 0.6;
            n.font = { color: '#86868B' }; // Text Secondary
        }

        // Icons
        if (n.group === NodeGroups.STATION) {
            n.shape = 'icon';
            let iconCode = '\uf10b'; // mobile-alt
            let color = '#FF453A'; // System Red (Default)

            const os = (n.os || '').toLowerCase();
            const model = (n.model || '').toLowerCase();

            if (os.includes('ios') || os.includes('apple')) {
                iconCode = '\uf179';
                color = '#F5F5F7'; // Apple White
            }
            else if (os.includes('android')) {
                iconCode = '\uf17b';
                color = '#30D158'; // System Green
            }
            else if (os.includes('windows') || model.includes('pc')) {
                iconCode = '\uf108'; // Desktop
                color = '#0A84FF'; // System Blue
            }
            else if (model.includes('camera')) {
                iconCode = '\uf030';
                color = '#FFD60A'; // System Yellow
            }
            else if (model.includes('tv')) {
                iconCode = '\uf26c';
                color = '#BF5AF2'; // System Purple
            }

            n.icon = { face: '"Font Awesome 6 Free"', code: iconCode, size: 24, color: color, weight: 'bold' };

            // Highlight Alias with Gold Icon
            if (State.getAlias(n.mac)) n.icon.color = '#FFD60A';

        } else if (n.group === NodeGroups.AP) {
            n.shape = 'icon';
            n.icon = { face: '"Font Awesome 6 Free"', code: '\uf1eb', size: 36, color: '#30D158', weight: 'bold' }; // System Green
            n.shadow = { color: 'rgba(48, 209, 88, 0.4)', size: 12, x: 0, y: 0 };

            // Handshake Captured (Lock Badge)
            if (n.has_handshake) {
                if (!n.label) n.label = '';
                if (!n.label.includes('🔒')) {
                    n.label += ' 🔒';
                }
            }
        }

        return n;
    },

    styleEdge(e) {
        // Simplified Logic: Dynamic coloring based on RSSI
        let color = 'rgba(0, 240, 255, 0.2)';
        let width = 1;

        if (e.type === 'correlation') {
            color = '#ffcc00';
            width = 3;
        } else if (e.type === 'inferred') {
            color = 'rgba(50, 215, 75, 0.5)';
            width = 2;
        }

        // Use backend provided color if available
        if (e.color) {
            color = e.color;
            if (e.label === 'auth failed' || color === '#ff453a') {
                width = 2; // Make red lines slightly thicker
            }
        }

        return {
            id: `${e.from}-${e.to}`,
            from: e.from,
            to: e.to,
            dashes: e.dashed || false,
            label: e.label,
            width: width,
            color: { color: color, highlight: color },
            font: { size: 10, align: 'middle', color: '#888' }
        };
    }
};
