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

        const icon = document.createElement('i');
        // Set icon class based on type
        if (type === 'success') icon.className = 'fas fa-check-circle';
        else if (type === 'warning') icon.className = 'fas fa-exclamation-triangle';
        else if (type === 'danger') icon.className = 'fas fa-radiation';
        else icon.className = 'fas fa-info-circle';

        note.appendChild(icon);
        note.appendChild(document.createTextNode(' ' + message));

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
