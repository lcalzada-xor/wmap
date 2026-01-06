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
            console.log("WS Connected");
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

        this.ws.onclose = () => {
            console.warn("WS Disconnected");
            this.onStatusChange("OFFLINE", "danger");
            setTimeout(() => this.connect(), this.reconnectInterval);
        };

        this.ws.onerror = (err) => {
            console.error("WS Error", err);
            this.ws.close();
        };
    }
}
