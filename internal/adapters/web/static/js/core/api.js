/**
 * WMAP API Wrapper
 * Handles all HTTP communication with the backend.
 */

export const API = {
    /**
     * Generic request handler with enhanced error handling
     */
    async request(endpoint, options = {}) {
        try {
            const res = await fetch(endpoint, options);

            // Handle different status codes
            if (res.status === 401) {
                // Redirect immediately and stop execution
                setTimeout(() => {
                    window.location.href = '/login.html';
                }, 0);
                throw Object.assign(new Error('Unauthorized - redirecting to login'), { status: 401 });
            }

            if (res.status === 403) {
                const text = await res.text();
                throw Object.assign(new Error(text || 'Forbidden'), { status: 403 });
            }

            if (res.status === 429) {
                throw Object.assign(new Error('Rate limit exceeded. Please try again later.'), { status: 429 });
            }

            if (!res.ok) {
                const text = await res.text();
                throw Object.assign(
                    new Error(text || `Request failed: ${res.statusText}`),
                    { status: res.status }
                );
            }

            return res.json().catch(() => ({})); // Handle empty JSON responses
        } catch (error) {
            // Network errors (no response from server)
            if (!error.status) {
                throw Object.assign(error, { status: 0, isNetworkError: true });
            }
            throw error;
        }
    },

    async get(endpoint) {
        return this.request(endpoint);
    },

    async post(endpoint, body) {
        return this.request(endpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body)
        });
    },

    // User & Auth
    async getMe() {
        return this.get('/api/me');
    },

    // Configuration
    async getConfig() {
        return this.get('/api/config');
    },

    // Workspaces
    async getWorkspaceStatus() {
        return this.get('/api/workspace/status');
    },

    async listWorkspaces() {
        return this.get('/api/workspaces');
    },

    async createWorkspace(name) {
        return this.post('/api/workspaces/new', { name });
    },

    async loadWorkspace(name) {
        return this.post('/api/workspaces/load', { name });
    },

    async clearWorkspace() {
        return this.post('/api/workspaces/clear', {});
    },

    // Scanning
    async triggerScan() {
        return this.post('/api/scan', {});
    },

    // Interfaces
    async getInterfaces() {
        return this.get('/api/interfaces');
    },

    // Channels
    async getChannels(iface) {
        let url = '/api/channels';
        if (iface) {
            url += `?interface=${encodeURIComponent(iface)}`;
        }
        return this.get(url);
    },

    async updateChannels(channels, iface) {
        return this.post('/api/channels', { channels, interface: iface });
    },

    // Deauth Attacks
    async startDeauthAttack(config) {
        return this.post('/api/deauth/start', config);
    },

    async stopDeauthAttack(attackId) {
        return this.post(`/api/deauth/stop?id=${attackId}`, {});
    },

    async getDeauthStatus(attackId) {
        return this.get(`/api/deauth/status?id=${attackId}`);
    },

    async listDeauthAttacks() {
        return this.get('/api/deauth/list');
    },

    // Audit Logs
    async getAuditLogs() {
        return this.get('/api/audit-logs');
    }
};
