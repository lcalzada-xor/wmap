/**
 * Trails Renderer
 */

import { State } from '../core/state.js';

export class TrailsRenderer {
    constructor(networkInstance, getCurrentNodes) {
        this.network = networkInstance;
        this.getNodes = getCurrentNodes; // Function returning current Node IDs
        this.trails = new Map(); // id -> [{x,y,time}]
    }

    enabled() {
        return State.config.trails;
    }

    draw(ctx, w, h) {
        if (!this.network) return;

        const nodeIds = this.getNodes();
        const positions = this.network.getPositions(nodeIds);
        const now = Date.now();

        nodeIds.forEach(id => {
            if (!positions[id]) return;
            const currentPos = positions[id];

            // Init history
            if (!this.trails.has(id)) this.trails.set(id, []);
            const trail = this.trails.get(id);

            // Add point logic (jitter reduction)
            if (trail.length > 0) {
                const last = trail[trail.length - 1];
                const dist = Math.sqrt(Math.pow(currentPos.x - last.x, 2) + Math.pow(currentPos.y - last.y, 2));
                if (dist < 2) return;
            }
            // Trail Limit: Keep strictly short
            trail.push({ x: currentPos.x, y: currentPos.y, time: now });

            // Prune: Keep them short and sweet (max 30 points or 1s)
            while (trail.length > 30 || (trail.length > 0 && now - trail[0].time > 1000)) {
                trail.shift();
            }

            if (trail.length < 2) return;

            // --- Minimalist Render Logic ---
            // Single pass, very subtle gradient

            const points = trail.map(p => this.network.canvasToDOM(p));

            // Visibility Check
            if (points[0].x < 0 || points[0].x > w || points[0].y < 0 || points[0].y > h) return;

            ctx.lineCap = 'round';
            ctx.lineJoin = 'round';
            ctx.globalAlpha = 1.0;
            ctx.shadowBlur = 0; // No shadow to prevent flicker

            // Create gradient stroke
            // Opacity fades from 0 (tail) to 0.5 (head)
            if (points.length > 1) {
                const head = points[points.length - 1];
                const tail = points[0];
                const grad = ctx.createLinearGradient(tail.x, tail.y, head.x, head.y);
                grad.addColorStop(0, "rgba(10, 132, 255, 0)");
                grad.addColorStop(1, "rgba(10, 132, 255, 0.5)"); // Max opacity 0.5

                ctx.strokeStyle = grad;
                ctx.lineWidth = 1.5; // Thin, elegant line

                ctx.beginPath();
                ctx.moveTo(points[0].x, points[0].y);
                for (let i = 1; i < points.length; i++) {
                    ctx.lineTo(points[i].x, points[i].y);
                }
                ctx.stroke();
            }
        });
    }
}
