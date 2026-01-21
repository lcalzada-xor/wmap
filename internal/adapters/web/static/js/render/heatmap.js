/**
 * Heatmap Renderer
 */

import { Store } from '../core/store/store.js';

export class HeatmapRenderer {
    constructor(networkInstance, nodesDataSet) {
        this.network = networkInstance;
        this.nodes = nodesDataSet;
    }

    enabled() {
        return Store.state.config.heatmap;
    }

    draw(ctx, w, h) {
        if (!this.network) return;

        // Note: Accessing DataSet is synchronous and fast enough for < 1000 nodes
        // Optimization: Get visible nodes only if possible, but getPositions(all) allows map wide heatmap
        const nodeIds = this.nodes.getIds();
        const positions = this.network.getPositions(nodeIds);

        ctx.globalCompositeOperation = 'lighter';

        const now = Date.now();

        nodeIds.forEach(id => {
            const node = this.nodes.get(id);
            if (!node || node.rssi === undefined) return;
            if (!positions[id]) return;

            const pos = this.network.canvasToDOM(positions[id]);

            // Culling
            if (pos.x < -200 || pos.x > w + 200 || pos.y < -200 || pos.y > h + 200) return;

            const rssi = parseFloat(node.rssi);

            // "Heat" Colors - Spatial Palette
            // Using mapped RGB values for smoother mixing
            let color = '10, 132, 255'; // Default Blue
            let opacityBase = 0.12; // Reduced from 0.3
            let radiusBase = 120;

            if (rssi >= -50) {
                color = '48, 209, 88'; // Green
                opacityBase = 0.25; // Reduced from 0.6
                radiusBase = 250;
            } else if (rssi >= -65) {
                color = '94, 92, 230'; // Indigo
                opacityBase = 0.2; // Reduced from 0.5
                radiusBase = 200;
            } else if (rssi >= -75) {
                color = '191, 90, 242'; // Purple
                opacityBase = 0.15; // Reduced from 0.4
                radiusBase = 150;
            } else if (rssi >= -90) {
                color = '255, 69, 58'; // Red
                opacityBase = 0.1; // Reduced from 0.25
                radiusBase = 100;
            }

            const scale = this.network.getScale();
            // Pulse Effect: Subtle breathing based on RSSI strength
            // Stronger signal = faster pulse
            const pulseSpeed = rssi >= -60 ? 0.005 : 0.002;

            // Fix: Hash string ID to number for phase offset
            let idNum = 0;
            if (typeof id === 'string') {
                for (let i = 0; i < id.length; i++) idNum = (idNum << 5) - idNum + id.charCodeAt(i);
            } else {
                idNum = id;
            }

            const pulse = 1 + Math.sin(now * pulseSpeed + idNum) * 0.05;

            const drawRadius = radiusBase * scale * pulse;
            if (drawRadius < 5) return;

            const grad = ctx.createRadialGradient(pos.x, pos.y, 0, pos.x, pos.y, drawRadius);
            // Non-linear falloff for "Glow" look
            grad.addColorStop(0, `rgba(${color}, ${opacityBase})`);
            grad.addColorStop(0.3, `rgba(${color}, ${opacityBase * 0.5})`);
            grad.addColorStop(0.7, `rgba(${color}, ${opacityBase * 0.1})`);
            grad.addColorStop(1, `rgba(${color}, 0)`);

            ctx.fillStyle = grad;
            ctx.beginPath();
            ctx.arc(pos.x, pos.y, drawRadius, 0, 2 * Math.PI);
            ctx.fill();
        });

        ctx.globalCompositeOperation = 'source-over';
    }
}
