/**
 * WMAP WebSocket Client
 * Handles real-time data updates.
 */

import { Actions } from './store/actions.js';
import { Store } from './store/store.js';

export class SocketClient {
    constructor() {
        this.socket = null;
        this.reconnectAttempts = 0;
        this.maxReconnectAttempts = 5;
    }

    connect() {
        Store.dispatch(Actions.SOCKET_CONNECTING);

        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        this.socket = new WebSocket(`${protocol}//${window.location.host}/ws`);

        this.socket.onopen = () => {
            console.log("WebSocket connected");
            this.reconnectAttempts = 0;
            Store.dispatch(Actions.SOCKET_CONNECTED);
        };

        this.socket.onmessage = (event) => {
            try {
                const msg = JSON.parse(event.data);
                this.handleMessage(msg);
            } catch (e) {
                console.error("Failed to parse WS message", e);
            }
        };

        this.socket.onclose = () => {
            console.log("WebSocket disconnected");
            Store.dispatch(Actions.SOCKET_DISCONNECTED);
            this.handleReconnect();
        };

        this.socket.onerror = (error) => {
            console.error("WebSocket error", error);
            Store.dispatch(Actions.SOCKET_ERROR, error);
        };
    }

    handleMessage(msg) {
        // Dispatch specific actions based on message type
        // This replaces the switch statement in main.js

        let type = msg.type;
        let payload = msg.payload;

        // Legacy format fallback
        if (!type && msg.nodes && msg.edges) {
            type = 'graph';
            payload = msg;
        }

        switch (type) {
            case 'graph':
                Store.dispatch(Actions.GRAPH_UPDATED, payload);
                break;
            case 'log':
                Store.dispatch(Actions.LOG_RECEIVED, payload);
                break;
            case 'alert':
                Store.dispatch(Actions.ALERT_RECEIVED, payload);
                break;
            case 'wps.log':
                Store.dispatch(Actions.WPS_LOG_RECEIVED, payload);
                break;
            case 'wps.status':
                Store.dispatch(Actions.WPS_STATUS_UPDATED, payload);
                break;
            case 'vulnerability:new':
                Store.dispatch(Actions.VULNERABILITY_DETECTED, payload);
                break;
            default:
                console.warn("Unknown message type:", type);
        }
    }

    handleReconnect() {
        if (this.reconnectAttempts < this.maxReconnectAttempts) {
            this.reconnectAttempts++;
            setTimeout(() => this.connect(), 2000 * this.reconnectAttempts);
        }
    }
}
