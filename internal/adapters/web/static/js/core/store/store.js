/**
 * WMAP Central Store
 * Single source of truth for application state.
 * Implements a Pub/Sub pattern for unidirectional data flow.
 */

import { Actions } from './actions.js';

export const Store = {
    // 1. State - The single source of truth
    state: {
        user: null,
        status: {
            connected: false,
            text: 'DISCONNECTED',
            type: 'danger'
        },

        // Runtime Data
        lastGraphUpdate: null,
        latestLog: null,
        latestAlert: null,

        // Configuration (Migrated from State.config)
        config: {
            grid: true,
            trails: true,
            heatmap: true,
            physics: true,
        },

        // Filters (Migrated from State.filters)
        filters: {
            // Basic
            showAP: true,
            showSta: true,
            persistFindings: true,
            minRSSI: -100,
            searchQuery: '',

            // Advanced
            vulnerabilities: [],
            security: [],
            frequency: [],
            channels: [],
            vendors: [],
            signalRange: { min: -100, max: 0 },
            timeRange: { lastSeen: null },
            traffic: { minTx: 0, minRx: 0, minPackets: 0 },

            // Booleans
            hasHandshake: false,
            hiddenSSID: false,
            wpsActive: false,
            randomizedMac: false,

            activePreset: null
        },

        // Domain Data
        aliases: JSON.parse(localStorage.getItem('wmap_aliases')) || {}
    },

    // 2. Listeners - Subscribed callbacks
    listeners: new Map(), // Action -> Set<Callback>

    // Initialize the store
    init() {
        console.log("Store: Initialized");
        // We could load persisted state here (localStorage)
    },

    // 3. Dispatch - The only way to update state
    dispatch(action, payload) {
        // console.debug(`[Store] Dispatch: ${action}`, payload);

        // A. Mutate State (Reducers logic inline for simplicity)
        this._reduce(action, payload);

        // B. Notify Listeners
        if (this.listeners.has(action)) {
            this.listeners.get(action).forEach(callback => {
                try {
                    callback(payload, this.state);
                } catch (err) {
                    console.error(`Store: Error in listener for ${action}`, err);
                }
            });
        }

        // Notify global listeners (optional, good for debugging)
        if (this.listeners.has('*')) {
            this.listeners.get('*').forEach(callback => callback(action, payload, this.state));
        }
    },

    // Internal reducer - Pure state mutation
    _reduce(action, payload) {
        switch (action) {
            case Actions.USER_LOGGED_IN:
                this.state.user = payload;
                break;
            case Actions.SOCKET_CONNECTED:
                this.state.status.connected = true;
                this.state.status.text = 'CONNECTED';
                this.state.status.type = 'success';
                break;
            case Actions.SOCKET_DISCONNECTED:
                this.state.status.connected = false;
                this.state.status.text = 'DISCONNECTED';
                this.state.status.type = 'danger';
                break;
            case Actions.SOCKET_CONNECTING:
                this.state.status.text = 'CONNECTING...';
                this.state.status.type = 'info';
                break;
            case Actions.GRAPH_UPDATED:
                this.state.lastGraphUpdate = Date.now();
                break;
            case Actions.LOG_RECEIVED:
                this.state.latestLog = payload;
                break;
            case Actions.ALERT_RECEIVED:
                this.state.latestAlert = payload;
                break;

            // --- New Phase 2 Handlers ---

            case Actions.CONFIG_UPDATED:
                // payload: { key: 'grid', value: false }
                if (payload && payload.key) {
                    this.state.config[payload.key] = payload.value;
                }
                break;

            case Actions.FILTER_UPDATED:
                // payload: { key: 'minRSSI', value: -80 }
                if (payload && payload.key) {
                    this.state.filters[payload.key] = payload.value;
                }
                break;

            case Actions.FILTER_BATCH_UPDATED:
                // payload: { showAP: true, minRSSI: -90, ... }
                if (payload) {
                    Object.assign(this.state.filters, payload);
                }
                break;

            case Actions.FILTER_RESET:
                // Reset complex objects if needed, or simple properties
                if (payload && payload.key) {
                    // Logic to reset specific filter
                }
                break;

            case Actions.ALIAS_UPDATED:
                // payload: { mac: '00:11...', alias: 'My iPhone' }
                if (payload && payload.mac) {
                    this.state.aliases[payload.mac] = payload.alias;
                    localStorage.setItem('wmap_aliases', JSON.stringify(this.state.aliases));
                }
                break;
        }
    },

    // 4. Subscribe - Component registration
    subscribe(action, callback) {
        if (!this.listeners.has(action)) {
            this.listeners.set(action, new Set());
        }
        this.listeners.get(action).add(callback);

        // Return unsubscribe function
        return () => {
            if (this.listeners.has(action)) {
                this.listeners.get(action).delete(callback);
            }
        };
    },

    // Get a snapshot of state
    getState() {
        return { ...this.state };
    }
};
