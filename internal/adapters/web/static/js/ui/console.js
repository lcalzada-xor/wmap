export class ConsoleManager {
    constructor() {
        this.isOpen = false;
        this.logs = [];
        this.maxLogs = 200; // Keep memory check

        // DOM Elements
        this.panel = null;
        this.list = null;
        this.toggleBtn = null;
        this.indicatorObj = null; // notification badge
    }

    init() {
        this.panel = document.getElementById('console-panel');
        this.list = document.getElementById('console-list');
        this.toggleBtn = document.getElementById('console-toggle');
        this.clearBtn = document.getElementById('console-clear');
        this.indicatorObj = document.getElementById('console-indicator');

        if (!this.panel || !this.list || !this.toggleBtn) {
            console.error("Console DOM elements not found");
            return;
        }

        // Event Listeners
        this.toggleBtn.addEventListener('click', () => this.toggle());

        if (this.clearBtn) {
            this.clearBtn.addEventListener('click', (e) => {
                e.stopPropagation();
                this.clear();
            });
        }

        // Global shortcut (optional)
        document.addEventListener('keydown', (e) => {
            if (e.ctrlKey && e.key === '`') {
                this.toggle();
            }
        });

        this.log("Console initialized. Ready for events.", "system");
    }

    toggle() {
        this.isOpen = !this.isOpen;
        if (this.isOpen) {
            this.panel.classList.add('open');
            this.toggleBtn.classList.add('active');
            this.scrollToBottom();
            // Clear unread
            if (this.indicatorObj) this.indicatorObj.style.display = 'none';
        } else {
            this.panel.classList.remove('open');
            this.toggleBtn.classList.remove('active');
        }
    }

    /**
     * @param {string} message 
     * @param {'info'|'warning'|'danger'|'success'|'system'} level 
     */
    log(message, level = 'info') {
        const timestamp = new Date().toLocaleTimeString();
        const entry = {
            id: Date.now(),
            timestamp,
            message,
            level
        };

        this.logs.push(entry);
        if (this.logs.length > this.maxLogs) {
            this.logs.shift();
            if (this.list.firstChild) {
                this.list.removeChild(this.list.firstChild);
            }
        }

        this.renderEntry(entry);

        // Auto-scroll if near bottom
        if (this.isOpen) {
            this.scrollToBottom();
        } else {
            // Show indicator if closed
            if (this.indicatorObj) {
                this.indicatorObj.style.display = 'block';
                this.indicatorObj.classList.add('pulse');
                setTimeout(() => this.indicatorObj.classList.remove('pulse'), 1000);
            }
        }
    }

    renderEntry(entry) {
        if (!this.list) return;

        const el = document.createElement('div');
        el.className = `console-entry entry-${entry.level}`;

        let icon = '';
        switch (entry.level) {
            case 'info': icon = '<i class="fas fa-info-circle"></i>'; break;
            case 'warning': icon = '<i class="fas fa-exclamation-triangle"></i>'; break;
            case 'danger': icon = '<i class="fas fa-biohazard"></i>'; break;
            case 'success': icon = '<i class="fas fa-check-circle"></i>'; break;
            case 'system': icon = '<i class="fas fa-terminal"></i>'; break;
        }

        el.innerHTML = `
            <span class="entry-time">[${entry.timestamp}]</span>
            <span class="entry-icon">${icon}</span>
            <span class="entry-msg">${entry.message}</span>
        `;

        this.list.appendChild(el);
    }

    clear() {
        this.logs = [];
        if (this.list) this.list.innerHTML = '';
        this.log("Console cleared.", "system");
    }

    scrollToBottom() {
        if (this.list) {
            this.list.scrollTop = this.list.scrollHeight;
        }
    }
}
