/**
 * Grid Renderer
 */

import { State } from '../core/state.js';

export class GridRenderer {
    constructor(networkInstance) {
        this.network = networkInstance;
    }

    enabled() {
        return State.config.grid;
    }

    draw(ctx, w, h) {
        if (!this.network) return;

        const scale = this.network.getScale();
        const centerDOM = this.network.canvasToDOM({ x: 0, y: 0 });

        ctx.save();

        // Spatial Dot Grid
        // Adjustable density based on zoom to prevent "dense blob" effect at low scale
        let baseStep = 100;

        // If scale is very low (zoomed out), increase step size to maintain apparent density
        // Logic: specific screen pixel gap (e.g. 50px) / scale = world units
        if (scale < 0.2) baseStep = 500;
        else if (scale < 0.5) baseStep = 250;

        const worldStep = baseStep;
        const dotSize = 1.5;

        // Fade grid out when extremely zoomed out to reduce noise
        const masterAlpha = scale < 0.05 ? 0 : (scale < 0.1 ? (scale - 0.05) / 0.05 : 1);
        if (masterAlpha <= 0) {
            ctx.restore();
            return;
        }

        // Convert screen bounds
        const topLeft = this.network.DOMtoCanvas({ x: 0, y: 0 });
        const bottomRight = this.network.DOMtoCanvas({ x: w, y: h });

        // Calculate visible range ensuring alignment
        const startX = Math.floor(topLeft.x / worldStep) * worldStep;
        const startY = Math.floor(topLeft.y / worldStep) * worldStep;

        // Guard against infinite loops if something goes wrong with coords
        // Max iterations check not strictly needed with correct step logic, but good for safety

        for (let x = startX; x < bottomRight.x; x += worldStep) {
            for (let y = startY; y < bottomRight.y; y += worldStep) {
                const domPos = this.network.canvasToDOM({ x: x, y: y });

                // Bounds check
                if (domPos.x < -10 || domPos.x > w + 10 || domPos.y < -10 || domPos.y > h + 10) continue;

                // Distance fade (Spatial feeling)
                // Calculate distance from center of screen
                const dist = Math.hypot(domPos.x - w / 2, domPos.y - h / 2);
                const maxDist = Math.max(w, h) * 0.8;
                let alpha = Math.max(0, 1 - (dist / maxDist)) * 0.4;

                // Combine with master zoom opacity
                alpha *= masterAlpha;

                if (alpha > 0.01) {
                    ctx.fillStyle = `rgba(255, 255, 255, ${alpha})`;
                    ctx.beginPath();
                    // Keep dots consistent size on screen, or subtle scaling?
                    // Fixed visual size (dotSize) vs scaled size (dotSize * scale).
                    // Fixed size (dotSize) ensures visibility at low zoom.
                    ctx.arc(domPos.x, domPos.y, dotSize, 0, Math.PI * 2);
                    ctx.fill();
                }
            }
        }

        // Origin Marker (Subtle crosshair)
        if (centerDOM.x > 0 && centerDOM.x < w && centerDOM.y > 0 && centerDOM.y < h) {
            ctx.strokeStyle = 'rgba(10, 132, 255, 0.6)';
            ctx.lineWidth = 2;
            ctx.beginPath();
            ctx.moveTo(centerDOM.x - 15, centerDOM.y); ctx.lineTo(centerDOM.x + 15, centerDOM.y);
            ctx.moveTo(centerDOM.x, centerDOM.y - 15); ctx.lineTo(centerDOM.x, centerDOM.y + 15);
            ctx.stroke();

            // Glow
            ctx.shadowColor = '#0A84FF';
            ctx.shadowBlur = 10;
            ctx.stroke();
            ctx.shadowBlur = 0;
        }

        ctx.restore();
    }
}
