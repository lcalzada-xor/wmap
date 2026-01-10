import { API } from '../core/api.js';
import { EventBus } from '../core/event_bus.js';
import { Events } from '../core/constants.js';

export class AuditManager {
    constructor() {
        this.modal = document.getElementById('audit-modal');
        this.btnShow = document.getElementById('btn-show-audit');
        this.btnClose = document.getElementById('btn-close-audit');
        this.btnRefresh = document.getElementById('btn-refresh-audit');
        this.loading = document.getElementById('audit-loading');
        this.tbody = document.getElementById('audit-list');

        this.init();
    }

    init() {
        if (this.btnShow) {

            this.btnShow.onclick = () => {

                this.open();
            };
        } else {
            console.error("AuditManager: Start button not found in DOM");
        }
        if (this.btnClose) {
            this.btnClose.onclick = () => this.close();
        }
        if (this.btnRefresh) {
            this.btnRefresh.onclick = () => this.fetchLogs();
        }

        // Close on outside click
        window.addEventListener('click', (e) => {
            if (e.target === this.modal) this.close();
        });

        // Real-time updates
        EventBus.on(Events.LOG, () => {
            if (this.isOpen()) {
                this.fetchLogs();
            }
        });
    }

    isOpen() {
        return this.modal && this.modal.style.display === 'flex';
    }

    open() {
        if (!this.modal) return;
        this.modal.classList.add('active'); // Use CSS class for opacity transition
        this.fetchLogs();
    }

    close() {
        if (this.modal) this.modal.classList.remove('active');
    }

    async fetchLogs() {
        this.loading.style.display = 'block';
        this.tbody.innerHTML = '';

        try {
            const data = await API.getAuditLogs();
            this.render(data.logs || []);
        } catch (err) {
            console.error("Failed to load audit logs:", err);
            this.tbody.innerHTML = `<tr><td colspan="5" style="text-align:center; padding:20px; color:var(--danger-color)">Failed to load logs. Ensure you are Admin.</td></tr>`;
        } finally {
            this.loading.style.display = 'none';
        }
    }

    render(logs) {
        if (logs.length === 0) {
            this.tbody.innerHTML = `<tr><td colspan="5" style="text-align:center; padding:20px; opacity:0.6;">No audit records found.</td></tr>`;
            return;
        }

        this.tbody.innerHTML = logs.map(log => {
            const date = new Date(log.timestamp).toLocaleString();
            let actionColor = '#fff';
            if (log.action.includes('START')) actionColor = 'var(--danger-color)';
            if (log.action.includes('STOP')) actionColor = 'var(--warning-color)';
            if (log.action.includes('LOGIN')) actionColor = 'var(--success-color)';

            return `
                <tr style="border-bottom: 1px solid rgba(255,255,255,0.05); transition: background 0.2s;">
                    <td style="padding: 10px; font-size: 0.9em; opacity: 0.8;">${date}</td>
                    <td style="padding: 10px; font-weight: 500;">${log.username || 'System'}</td>
                    <td style="padding: 10px; color: ${actionColor}; font-weight: 600;">${log.action}</td>
                    <td style="padding: 10px; font-family: monospace;">${log.target}</td>
                    <td style="padding: 10px; font-size: 0.9em; opacity: 0.8;">${log.details}</td>
                </tr>
            `;
        }).join('');
    }
}
