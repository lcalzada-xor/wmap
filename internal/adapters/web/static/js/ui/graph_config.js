/**
 * Graph Configuration
 * Static configuration for Vis.js Network
 */
export const GraphConfig = {
    nodes: {
        font: { face: 'SF Pro Text, Inter, sans-serif', color: '#F5F5F7', size: 14, strokeWidth: 0, vadjust: -30 },
        borderWidth: 1, // Elegant thin border
        shadow: { enabled: true, color: 'rgba(0,0,0,0.5)', size: 8, x: 0, y: 4 }, // Soft shadow
        shape: 'dot',
        size: 10,
        color: {
            background: '#1C1C1E', // Apple Dark Grey
            border: '#ffffff',
            highlight: { background: '#ffffff', border: '#0A84FF' } // System Blue
        }
    },
    edges: {
        color: {
            color: 'rgba(255, 255, 255, 0.15)', // Subtle connection
            highlight: '#ffffff',
            hover: '#ffffff',
            inherit: false
        },
        width: 1,
        shadow: { enabled: false }, // No glowing edges, clean lines
        smooth: { type: 'continuous', forceDirection: 'none', roundness: 0.5 }
    },
    physics: {
        stabilization: false,
        barnesHut: {
            gravitationalConstant: -8000,
            centralGravity: 0.4,
            springLength: 150,
            springConstant: 0.05,
            damping: 0.2,
            avoidOverlap: 0.1
        },
        minVelocity: 0.75,
        timestep: 0.4
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
