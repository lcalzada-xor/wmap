/**
 * Graph Configuration
 * Static configuration for Vis.js Network
 */
export const GraphConfig = {
    nodes: {
        font: { face: 'SF Pro Text, Inter, sans-serif', color: '#F5F5F7', size: 14, strokeWidth: 4, strokeColor: '#000000' },
        borderWidth: 0,
        shadow: { enabled: true, color: 'rgba(0,0,0,0.5)', size: 10, x: 0, y: 4 },
        shape: 'dot',
        size: 10,
        color: {
            background: '#86868B',
            border: '#ffffff',
            highlight: { background: '#ffffff', border: '#0A84FF' }
        }
    },
    edges: {
        color: {
            color: 'rgba(0, 240, 255, 0.8)', /* Neon Cyan - Increased Opacity */
            highlight: '#ffffff',
            hover: '#ffffff'
        },
        width: 3, /* Increased Width */
        shadow: { enabled: true, color: 'rgba(0, 240, 255, 0.6)', size: 10, x: 0, y: 0 },
        smooth: { type: 'continuous' }
    },
    physics: {
        stabilization: false,
        barnesHut: {
            gravitationalConstant: -10000, /* Stronger Repeals (was -3000) */
            centralGravity: 0.3,
            springLength: 250, /* Longer Springs (was 200) */
            springConstant: 0.04,
            damping: 0.09,
            avoidOverlap: 0.5 /* explicit overlap avoidance benefit */
        },
        timestep: 0.5
    },
    groups: {
        network: {
            shape: 'icon',
            icon: { face: '"Font Awesome 6 Free"', code: '\uf233', size: 40, color: '#0A84FF' }, // iOS Blue
            shadow: { enabled: true, color: 'rgba(10, 132, 255, 0.4)', size: 15 }
        },
        ap: {
            shape: 'icon',
            icon: { face: '"Font Awesome 6 Free"', code: '\uf1eb', size: 36, color: '#64D2FF' }, // iOS Cyan
            shadow: { enabled: true, color: 'rgba(100, 210, 255, 0.4)', size: 15 }
        },
        station: {
            shape: 'dot',
            size: 8,
            color: { background: '#30D158', border: '#ffffff', borderWidth: 2 }, // iOS Green
            shadow: { enabled: true, color: 'rgba(48, 209, 88, 0.4)', size: 10 }
        }
    },
    interaction: { hover: true, tooltipDelay: 200 }
};
