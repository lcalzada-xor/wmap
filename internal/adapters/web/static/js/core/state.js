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
    setAlias(mac, alias) {
        this.aliases[mac] = alias;
        localStorage.setItem('wmap_aliases', JSON.stringify(this.aliases));
    },

    getAlias(mac) {
        return this.aliases[mac] || null;
    }
};
