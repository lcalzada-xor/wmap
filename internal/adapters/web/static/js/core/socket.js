/**
 * WMAP WebSocket Client
 * Handles real-time data updates.
 */

export class SocketClient {
    constructor(onMessage, onStatusChange) {
        this.url = (location.protocol === 'https:' ? 'wss' : 'ws') + '://' + location.host + '/ws';
        this.ws = null;
        this.reconnectInterval = 3000;
        this.onMessage = onMessage;
        this.onStatusChange = onStatusChange || (() => { });
    }

    connect() {
        this.ws = new WebSocket(this.url);

        this.ws.onopen = () => {

            this.onStatusChange("ONLINE", "success");
        };

        this.ws.onmessage = (event) => {
            try {
                const data = JSON.parse(event.data);
                if (this.onMessage) this.onMessage(data);
            } catch (e) {
                console.error("WS Parse Error", e);
            }
        };

        this.ws.onclose = (event) => {
            console.warn("WS Disconnected", event.code, event.reason);

            // Check if it's an authentication error (401 Unauthorized or 403 Forbidden)
            if (event.code === 1008 || event.code === 1011) {
                console.error("WebSocket authentication failed - redirecting to login");
                window.location.href = '/login.html';
                return;
            }

            this.onStatusChange("OFFLINE", "danger");
            setTimeout(() => this.connect(), this.reconnectInterval);
        };

        this.ws.onerror = (err) => {
            console.error("WS Error", err);
            // Don't close here, let onclose handle it
        };
    }
}
