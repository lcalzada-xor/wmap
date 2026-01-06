/**
 * Graph Styler
 * Encapsulates visual logic for Nodes and Edges.
 */

import { State } from '../core/state.js';

export const GraphStyler = {
    styleNode(n) {
        // Notifications & Aliases
        if (State.getAlias(n.mac)) {
            n.label = State.getAlias(n.mac);
            n.font = { color: '#FFD60A' };
        }

        // WiFi Generation Styling
        if (n.is_wifi7) {
            n.borderWidth = 4;
            n.color = { border: '#b900ff', background: n.group === 'ap' ? 'rgba(185, 0, 255, 0.2)' : undefined };
            n.shadow = { color: '#b900ff', size: 15, x: 0, y: 0 };
        } else if (n.is_wifi6) {
            n.borderWidth = 2;
            n.color = { border: '#00f0ff' };
            n.shadow = { color: '#00f0ff', size: 12, x: 0, y: 0 };
        }

        // Randomized MAC
        if (n.is_randomized) {
            n.shadow = { enabled: true, color: 'rgba(255, 255, 255, 0.4)', size: 8, x: 0, y: 0 };
        }

        // Icons
        if (n.group === 'station') {
            n.shape = 'icon';
            let iconCode = '\uf390'; // mobile
            let color = '#FF453A';

            const os = (n.os || '').toLowerCase();
            const model = (n.model || '').toLowerCase();

            if (os.includes('ios') || os.includes('apple')) iconCode = '\uf179';
            else if (os.includes('android')) iconCode = '\uf17b';
            else if (os.includes('windows') || model.includes('pc')) iconCode = '\uf108';
            else if (model.includes('camera')) iconCode = '\uf030';
            else if (model.includes('tv')) iconCode = '\uf26c';

            n.icon = { face: '"Font Awesome 6 Free"', code: iconCode, size: 26, color: color, weight: '900' };

            // Highlight Alias with Yellow Icon
            if (State.getAlias(n.mac)) n.icon.color = '#FFD60A';

        } else if (n.group === 'ap') {
            n.shape = 'icon';
            n.icon = { face: '"Font Awesome 6 Free"', code: '\uf1eb', size: 32, color: '#32D74B', weight: '900' };
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
