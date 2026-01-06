/**
 * Render Compositor
 * Manages the animation loop and delegated renderers.
 */

import { State } from '../core/state.js';

export class Compositor {
    constructor() {
        this.renderers = [];
        this.running = false;
        this.canvas = document.getElementById('heatmap-layer');
        this.ctx = this.canvas ? this.canvas.getContext('2d') : null;

        this.resize();
        window.addEventListener('resize', () => this.resize());
    }

    addRenderer(renderer) {
        this.renderers.push(renderer);
    }

    resize() {
        if (!this.canvas) return;
        this.canvas.width = window.innerWidth;
        this.canvas.height = window.innerHeight;
    }

    start() {
        if (this.running) return;
        this.running = true;
        this.loop();
    }

    stop() {
        this.running = false;
    }

    loop() {
        if (!this.running) return;
        requestAnimationFrame(() => this.loop());

        // Optimization: Don't draw if disabled and cleared
        // But renderers might have their own state check

        if (!this.ctx) return;

        const w = this.canvas.width;
        const h = this.canvas.height;

        this.ctx.clearRect(0, 0, w, h);

        this.renderers.forEach(r => {
            if (r.enabled()) {
                r.draw(this.ctx, w, h);
            }
        });
    }
}
