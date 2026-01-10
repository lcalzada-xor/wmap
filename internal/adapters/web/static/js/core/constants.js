/**
 * WMAP Constants
 * Centralized definition of application constants.
 */

export const NodeGroups = {
    AP: 'ap',
    STATION: 'station',
    NETWORK: 'network',
    // Legacy/Fallback groupings
    ACCESS_POINT: 'accesspoint',
    CLIENT: 'client',
    STA: 'sta'
};

export const Colors = {
    SUCCESS: '#30D158',
    DANGER: '#FF453A',
    WARNING: '#FF9F0A',
    INFO: '#0A84FF',
    ACCENT: '#0A84FF', // System Blue

    // Signal Quality
    SIGNAL_STRONG: '#30D158',
    SIGNAL_GOOD: '#FFCF00',
    SIGNAL_WEAK: '#FF9F0A',

    // Node Types
    NODE_AP: '#30D158',
    NODE_STATION: '#FF453A',
    NODE_NETWORK: '#0A84FF'
};

export const Events = {
    PHYSICS: 'physics',
    VENDOR: 'vendor',
    CHANNELS: 'channels',
    SEARCH: 'search',
    CLEAR: 'clear',
    RESET: 'reset',
    LOG: 'log'
};

export const Timeouts = {
    // Time to wait for initial data before forcing UI render (fallback)
    INITIAL_DATA_WAIT: 2000
};
