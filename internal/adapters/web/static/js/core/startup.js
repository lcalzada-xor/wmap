/**
 * Startup Verifier
 * Checks for critical dependencies and DOM elements before app launch.
 */

export class StartupVerifier {
    static async verify() {
        // 1. Check for Critical DOM Elements
        const requiredIds = ['mynetwork', 'status', 'dynamic-island', 'console-panel'];
        const missing = requiredIds.filter(id => !document.getElementById(id));
        if (missing.length > 0) {
            throw new Error(`Critical DOM elements missing: ${missing.join(', ')}`);
        }

        // 2. Check for External Dependencies (Vis.js)
        if (typeof window.vis === 'undefined') {
            throw new Error("Vis.js library failed to load. Please check your internet connection or CDN availability.");
        }

        return true;
    }

    static reportError(msg) {
        console.error("Startup Error:", msg);
        const statusEl = document.getElementById('status');
        const islandEl = document.getElementById('dynamic-island');

        // Also try to log to our new console if it exists (might not if startup failed early)
        if (window.wmapApp && window.wmapApp.console) {
            window.wmapApp.console.log(msg, "danger");
        }

        if (statusEl) {
            statusEl.innerText = "SYSTEM ERROR";
            statusEl.style.color = "var(--danger-color)";
        }

        if (islandEl) {
            islandEl.style.borderColor = "var(--danger-color)";
        }

        // Show a more detailed alert if possible, or just replace the status text
        // For now, let's append a visible error message to the body for absolute clarity
        const errDiv = document.createElement('div');
        errDiv.style.position = 'fixed';
        errDiv.style.top = '50%';
        errDiv.style.left = '50%';
        errDiv.style.transform = 'translate(-50%, -50%)';
        errDiv.style.background = 'rgba(20, 0, 0, 0.95)';
        errDiv.style.border = '1px solid red';
        errDiv.style.padding = '20px';
        errDiv.style.color = '#ff4444';
        errDiv.style.zIndex = '9999';
        errDiv.style.fontFamily = 'monospace';
        errDiv.innerHTML = `<h3><u>INITIALIZATION FAILED</u></h3><p>${msg}</p>`;
        document.body.appendChild(errDiv);
    }
}
