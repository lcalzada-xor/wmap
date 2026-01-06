/**
 * WMAP API Wrapper
 * Handles all HTTP communication with the backend.
 */

export const API = {
    async get(endpoint) {
        const res = await fetch(endpoint);
        if (!res.ok) throw new Error(`GET ${endpoint} failed: ${res.statusText}`);
        return res.json();
    },

    async post(endpoint, body) {
        const res = await fetch(endpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body)
        });
        if (!res.ok) {
            const text = await res.text();
            throw new Error(text || `POST ${endpoint} failed`);
        }
        return res.json().catch(() => ({})); // Handle empty JSON responses
    },

    // Specific Endpoints
    async getConfig() {
        return this.get('/api/config');
    },

    async getSessionStatus() {
        return this.get('/api/session/status');
    },

    async listSessions() {
        return this.get('/api/sessions');
    },

    async createSession(name) {
        return this.post('/api/sessions/new', { name });
    },

    async loadSession(name) {
        return this.post('/api/sessions/load', { name });
    },

    async clearSession() {
        return this.post('/api/session/clear', {});
    },

    async triggerScan() {
        return this.post('/api/scan', {});
    },

    async getInterfaces() {
        return this.get('/api/interfaces');
    },

    async getChannels(iface) {
        let url = '/api/channels';
        if (iface) {
            url += `?interface=${encodeURIComponent(iface)}`;
        }
        return this.get(url);
    },

    async updateChannels(channels, iface) {
        return this.post('/api/channels', { channels, interface: iface });
    }
};
