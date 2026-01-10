/**
 * Notification System
 * Handles toast messages in the HUD.
 */

export const Notifications = {
    // DOM Elements (Cached)
    container: null,
    statusEl: null,
    islandEl: null,

    init() {
        this.container = document.getElementById('notification-area');
        this.statusEl = document.getElementById('status');
        this.islandEl = document.getElementById('dynamic-island');
    },

    show(message, type = 'info') {
        if (!this.container) this.init(); // Lazy init
        if (!this.container) {
            console.warn("Notification container not found, logging to console:", message);
            return;
        }

        const note = document.createElement('div');
        note.className = `notification ${type}`;
        note.innerHTML = `<i class="fas fa-info-circle"></i> ${message}`;

        // Icons
        if (type === 'success') note.innerHTML = `<i class="fas fa-check-circle"></i> ${message}`;
        if (type === 'warning') note.innerHTML = `<i class="fas fa-exclamation-triangle"></i> ${message}`;
        if (type === 'danger') note.innerHTML = `<i class="fas fa-radiation"></i> ${message}`;

        this.container.appendChild(note);

        // Slide In
        requestAnimationFrame(() => {
            note.style.opacity = '1';
            note.style.transform = 'translateX(0)';
        });

        // Auto Dismiss
        setTimeout(() => {
            note.style.opacity = '0';
            note.style.transform = 'translateX(20px)';
            setTimeout(() => note.remove(), 300);
        }, 4000);
    },

    setStatus(text, type = 'info') {
        if (!this.statusEl) this.init(); // Lazy init

        if (this.statusEl) {
            this.statusEl.innerText = text;
            this.statusEl.style.color = type === 'danger' ? 'var(--danger-color)' :
                type === 'success' ? 'var(--success-color)' : 'var(--text-primary)';
        }

        // Pulse Effect on Island
        if (this.islandEl) {
            this.islandEl.style.borderColor = type === 'danger' ? 'var(--danger-color)' :
                type === 'success' ? 'var(--success-color)' : 'rgba(255, 255, 255, 0.1)';
        }
    }
};
