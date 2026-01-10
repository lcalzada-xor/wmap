/**
 * WMAP Application State
 * Central store for configuration and runtime state.
 */

export const State = {
    // Config
    config: {
        grid: true,
        trails: true,
        heatmap: true,
        physics: true,
    },

    // Filters
    filters: {
        // Basic filters (existing)
        showAP: true,
        showSta: true,
        persistFindings: true,
        minRSSI: -100,
        searchQuery: '',

        // Advanced filters (new)
        vulnerabilities: [],    // ['WEP', 'WPS', 'KRACK', 'DRAGON']
        security: [],           // ['WPA2', 'WPA3', 'OPEN', 'WEP']
        frequency: [],          // ['2.4', '5']
        channels: [],           // [1, 6, 11, 36, 40, ...]
        vendors: [],            // ['Apple', 'Samsung', ...]
        signalRange: {          // Custom RSSI range
            min: -100,
            max: 0
        },
        timeRange: {            // Time-based filters
            lastSeen: null      // milliseconds or null
        },
        traffic: {              // Traffic-based filters
            minTx: 0,           // bytes
            minRx: 0,           // bytes
            minPackets: 0       // packet count
        },
        // Booleans (New)
        hasHandshake: false,
        hiddenSSID: false,
        wpsActive: false,
        randomizedMac: false,

        activePreset: null,     // Currently active preset ID
        searchHistory: []       // Last 10 searches
    },

    // Runtime Data
    aliases: JSON.parse(localStorage.getItem('wmap_aliases')) || {},
    knownNodes: new Set(),
    followingNode: null,
    clusteringEnabled: false,

    // Methods
    listeners: {},

    subscribe(key, callback) {
        if (!this.listeners[key]) {
            this.listeners[key] = [];
        }
        this.listeners[key].push(callback);
    },

    notify(key, value) {
        if (this.listeners[key]) {
            this.listeners[key].forEach(cb => cb(value));
        }
        // Also notify wildcard listeners if any (optional)
    },

    setAlias(mac, alias) {
        this.aliases[mac] = alias;
        localStorage.setItem('wmap_aliases', JSON.stringify(this.aliases));
        this.notify('aliases', this.aliases);
    },

    getAlias(mac) {
        return this.aliases[mac] || null;
    }
};

// Make filters reactive using Proxy
const filtersProxy = new Proxy(State.filters, {
    set(target, property, value) {
        target[property] = value;
        // Notify listeners of specific property change
        State.notify(property, value); // e.g. notify('searchQuery', 'test')
        State.notify('filters', target); // Notify generic 'filters' change
        return true;
    }
});

// Replace original filters with proxy
State.filters = filtersProxy;
