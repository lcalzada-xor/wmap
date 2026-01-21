import { API } from '../core/api.js';
import { EventBus } from '../core/event_bus.js';
import { Events } from '../core/constants.js';

/**
 * Audit Manager 2.0 (Master-Detail Layout)
 * Redesigned for iOS 19 Glassmorphism and enhanced utility.
 */
export class AuditManager {
    constructor() {
        this.btnShow = document.getElementById('btn-show-audit');
        this.overlay = null;
        this.container = null;

        this.logs = [];
        this.filteredLogs = [];
        this.selectedLogId = null;

        // State
        this.filters = {
            action: 'all', // 'all', 'start', 'stop', 'login', 'other'
            user: 'all',
            search: ''
        };
        this.sort = {
            by: 'time', // 'time', 'action', 'user'
            order: 'desc' // 'asc', 'desc'
        };

        this.loading = false;

        this.init();
    }

    init() {
        if (this.btnShow) {
            this.btnShow.onclick = () => this.toggle();
        } else {
            console.error("AuditManager: Start button not found in DOM");
        }

        // Real-time updates
        EventBus.on(Events.LOG, () => {
            if (this.isOpen()) {
                this.fetchLogs();
            }
        });
    }

    isOpen() {
        return this.overlay && this.overlay.style.display !== 'none';
    }

    /**
     * Toggles the panel visibility
     */
    toggle() {
        if (!this.overlay) this.createContainer();

        const isVisible = this.overlay.style.display !== 'none';

        if (isVisible) {
            // Close
            this.container.classList.remove('pop-in');
            setTimeout(() => {
                this.overlay.style.display = 'none';
            }, 300);
        } else {
            // Open
            this.overlay.style.display = 'flex';

            // Animation trigger
            requestAnimationFrame(() => {
                this.container.classList.add('pop-in');
            });

            this.fetchLogs();
        }
    }

    async fetchLogs() {
        this.loading = true;

        try {
            const data = await API.getAuditLogs();
            this.logs = (data.logs || []).map((log, idx) => ({
                ...log,
                id: idx // Add unique ID for selection
            }));

            // Apply local logic (search) and sort
            this.processData();

            // Select first item if nothing selected and items exist
            if (this.selectedLogId === null && this.filteredLogs.length > 0) {
                this.selectedLogId = this.filteredLogs[0].id;
            }

            this.render();

        } catch (err) {
            console.error("Failed to load audit logs:", err);
            this.logs = [];
            this.processData();
            this.render();
        } finally {
            this.loading = false;
        }
    }

    processData() {
        // 1. Filter locally
        let res = this.logs.filter(log => {
            const matchesSearch = log.action.toLowerCase().includes(this.filters.search) ||
                (log.username && log.username.toLowerCase().includes(this.filters.search)) ||
                (log.target && log.target.toLowerCase().includes(this.filters.search)) ||
                (log.details && log.details.toLowerCase().includes(this.filters.search));

            const matchesAction = this.filters.action === 'all' || this.getActionType(log.action) === this.filters.action;
            const matchesUser = this.filters.user === 'all' || log.username === this.filters.user;

            return matchesSearch && matchesAction && matchesUser;
        });

        // 2. Sort
        res.sort((a, b) => {
            let valA, valB;

            if (this.sort.by === 'time') {
                valA = new Date(a.timestamp).getTime();
                valB = new Date(b.timestamp).getTime();
            } else if (this.sort.by === 'action') {
                valA = a.action;
                valB = b.action;
            } else if (this.sort.by === 'user') {
                valA = a.username || 'System';
                valB = b.username || 'System';
            }

            if (valA < valB) return this.sort.order === 'asc' ? -1 : 1;
            if (valA > valB) return this.sort.order === 'asc' ? 1 : -1;
            return 0;
        });

        this.filteredLogs = res;
    }

    getActionType(action) {
        if (action.includes('START')) return 'start';
        if (action.includes('STOP')) return 'stop';
        if (action.includes('LOGIN')) return 'login';
        return 'other';
    }

    getActionClass(action) {
        const type = this.getActionType(action);
        return type === 'other' ? 'default' : type;
    }

    /* ---------------- UI Construction ---------------- */

    createContainer() {
        this.overlay = document.createElement('div');
        this.overlay.className = 'audit-modal-overlay';
        this.overlay.style.display = 'none';

        // Split View Container
        this.container = document.createElement('div');
        this.container.id = 'audit-panel-container';

        // --- Sidebar (Left) ---
        const sidebar = document.createElement('div');
        sidebar.className = 'audit-sidebar';
        sidebar.innerHTML = `
            <div class="audit-sidebar-header">
                <div class="audit-sidebar-title"><i class="fas fa-history" style="color:var(--accent-color)"></i> Audit Logs</div>
                
                <div class="audit-sidebar-controls">
                    <div class="audit-search-wrapper">
                        <i class="fas fa-search"></i>
                        <input type="text" id="audit-search-input" class="audit-search-input" placeholder="Search logs...">
                    </div>
                    <div class="audit-filter-row">
                        <select id="audit-filter-action" class="audit-select-compact">
                            <option value="all">All Actions</option>
                            <option value="start">Start</option>
                            <option value="stop">Stop</option>
                            <option value="login">Login</option>
                            <option value="other">Other</option>
                        </select>
                        <select id="audit-sort-mode" class="audit-select-compact">
                            <option value="time:desc">Newest First</option>
                            <option value="time:asc">Oldest First</option>
                            <option value="action:asc">Action A-Z</option>
                            <option value="user:asc">User A-Z</option>
                        </select>
                    </div>
                </div>
            </div>
            <div class="audit-list-container" id="audit-list-scroll">
                <!-- List Items Injected Here -->
            </div>
        `;

        // --- Detail View (Right) ---
        const detailView = document.createElement('div');
        detailView.className = 'audit-detail-view';
        detailView.innerHTML = `
            <button class="audit-close-btn"><i class="fas fa-times"></i></button>
            <div id="audit-detail-content" style="height:100%; display:flex; flex-direction:column;">
                <!-- Detail Content Injected Here -->
            </div>
        `;

        this.container.appendChild(sidebar);
        this.container.appendChild(detailView);
        this.overlay.appendChild(this.container);
        document.body.appendChild(this.overlay);

        this.bindEvents();
    }

    bindEvents() {
        // Close
        this.container.querySelector('.audit-close-btn').onclick = () => this.toggle();
        this.overlay.onclick = (e) => {
            if (e.target === this.overlay) this.toggle();
        };

        // Inputs
        const searchInput = this.container.querySelector('#audit-search-input');
        searchInput.oninput = (e) => {
            this.filters.search = e.target.value.toLowerCase();
            this.processData();
            this.renderList();
        };

        const actionSelect = this.container.querySelector('#audit-filter-action');
        actionSelect.onchange = (e) => {
            this.filters.action = e.target.value;
            this.processData();
            this.renderList();
        };

        const sortSelect = this.container.querySelector('#audit-sort-mode');
        sortSelect.onchange = (e) => {
            const [by, order] = e.target.value.split(':');
            this.sort.by = by;
            this.sort.order = order;
            this.processData();
            this.renderList();
        };
    }

    /* ---------------- Rendering ---------------- */

    render() {
        if (!this.container) return;
        this.renderList();
        this.renderDetail();
    }

    renderList() {
        const listContainer = this.container.querySelector('#audit-list-scroll');
        listContainer.innerHTML = '';

        if (this.filteredLogs.length === 0) {
            listContainer.innerHTML = `<div style="padding:20px; text-align:center; color:rgba(255,255,255,0.3); font-size:0.9rem;">No audit logs match your filters.</div>`;
            return;
        }

        this.filteredLogs.forEach(log => {
            const el = document.createElement('div');
            el.className = `audit-list-item ${this.selectedLogId === log.id ? 'selected' : ''}`;
            el.onclick = () => {
                this.selectedLogId = log.id;
                this.renderList(); // Update selection state
                this.renderDetail();
            };

            const actionClass = this.getActionClass(log.action);
            const date = new Date(log.timestamp);
            const timeStr = date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

            el.innerHTML = `
                <div class="audit-item-header">
                    <span class="audit-item-action">${log.action}</span>
                    <span class="action-dot ${actionClass}"></span>
                </div>
                <div class="audit-item-meta">
                    <span><i class="fas fa-user"></i> ${log.username || 'System'}</span>
                    <span style="margin-left:auto; font-size:0.75em; opacity:0.7;">${timeStr}</span>
                </div>
            `;
            listContainer.appendChild(el);
        });
    }

    renderDetail() {
        const detailContainer = this.container.querySelector('#audit-detail-content');

        // Find selected log
        const log = this.filteredLogs.find(l => l.id === this.selectedLogId);

        if (!log) {
            detailContainer.innerHTML = `
                <div class="audit-detail-empty-state">
                    <i class="fas fa-clipboard-list"></i>
                    <h3>Select a Log Entry</h3>
                    <p>Choose an audit log from the sidebar to view details.</p>
                </div>
            `;
            return;
        }

        const actionClass = this.getActionClass(log.action);
        const date = new Date(log.timestamp);
        const fullDate = date.toLocaleString();

        detailContainer.innerHTML = `
            <div class="audit-detail-header">
                <div class="audit-detail-title-group">
                    <div style="display:flex; gap:10px; align-items:center; margin-bottom:8px;">
                        <span class="action-badge ${actionClass}">${this.getActionType(log.action)}</span>
                        <span style="font-size:0.8rem; color:rgba(255,255,255,0.4);">${fullDate}</span>
                    </div>
                    <h2>${log.action}</h2>
                    <div class="audit-detail-meta-row">
                        <span><i class="fas fa-user"></i> User: <strong style="color:white;">${log.username || 'System'}</strong></span>
                        <span><i class="fas fa-bullseye"></i> Target: <strong style="color:white; font-family:var(--font-mono);">${log.target || 'N/A'}</strong></span>
                    </div>
                </div>
                <div class="audit-detail-actions">
                    <button class="audit-action-btn" id="btn-copy-log" title="Copy Log Details">
                        <i class="fas fa-copy"></i> Copy
                    </button>
                    <button class="audit-action-btn primary" id="btn-export-log" title="Export Log">
                        <i class="fas fa-download"></i> Export
                    </button>
                </div>
            </div>
            
            <div class="audit-detail-content">
                <div class="audit-detail-section">
                    <h4>Details</h4>
                    <p style="line-height:1.6; color:rgba(255,255,255,0.8);">${log.details || 'No additional details provided.'}</p>
                </div>

                <div class="audit-detail-section">
                    <h4>Technical Information</h4>
                    <div class="audit-info-grid">
                        <div class="audit-info-item">
                             <label>Timestamp</label>
                             <span>${fullDate}</span>
                        </div>
                        <div class="audit-info-item">
                             <label>Action Type</label>
                             <span>${this.getActionType(log.action).toUpperCase()}</span>
                        </div>
                        <div class="audit-info-item">
                             <label>User</label>
                             <span>${log.username || 'System'}</span>
                        </div>
                        <div class="audit-info-item">
                             <label>Target</label>
                             <span>${log.target || 'N/A'}</span>
                        </div>
                    </div>
                </div>

                <div class="audit-detail-section">
                    <h4>Raw Log Data</h4>
                    <pre class="audit-code-block">${JSON.stringify(log, null, 2)}</pre>
                </div>
            </div>
        `;

        // Bind Action Buttons
        const btnCopy = detailContainer.querySelector('#btn-copy-log');
        if (btnCopy) btnCopy.onclick = () => this.copyLogToClipboard(log);

        const btnExport = detailContainer.querySelector('#btn-export-log');
        if (btnExport) btnExport.onclick = () => this.exportLog(log);
    }

    /* ---------------- Helpers ---------------- */

    copyLogToClipboard(log) {
        const text = `Action: ${log.action}\nUser: ${log.username || 'System'}\nTarget: ${log.target || 'N/A'}\nTimestamp: ${new Date(log.timestamp).toLocaleString()}\nDetails: ${log.details || 'N/A'}`;

        navigator.clipboard.writeText(text).then(() => {
            // Show notification (if Notifications class is available)
            if (window.Notifications) {
                window.Notifications.show('Log copied to clipboard', 'success');
            } else {
                alert('Log copied to clipboard');
            }
        }).catch(err => {
            console.error('Failed to copy:', err);
            alert('Failed to copy log to clipboard');
        });
    }

    exportLog(log) {
        const dataStr = JSON.stringify(log, null, 2);
        const dataBlob = new Blob([dataStr], { type: 'application/json' });
        const url = URL.createObjectURL(dataBlob);
        const link = document.createElement('a');
        link.href = url;
        link.download = `audit_log_${log.id}_${Date.now()}.json`;
        link.click();
        URL.revokeObjectURL(url);

        if (window.Notifications) {
            window.Notifications.show('Log exported successfully', 'success');
        }
    }
}
