/**
 * WMAP Main Entry
 */

import { API } from './core/api.js';
import { State } from './core/state.js';
import { SocketClient } from './core/socket.js';

import { DataManager } from './graph/data.js';

import { Compositor } from './render/compositor.js';
import { GridRenderer } from './render/grid.js';
import { HeatmapRenderer } from './render/heatmap.js';
import { TrailsRenderer } from './render/trails.js';

import { Notifications } from './ui/notifications.js';
import { Modals } from './ui/modals.js';
import { HUD } from './ui/hud.js';

import { ContextMenu } from './ui/context_menu.js';
import { GraphConfig } from './ui/graph_config.js';
import { DeauthController } from './ui/deauth_controller.js';

// Vis.js Global because it's loaded via script tag (UMD)
const vis = window.vis;

class App {
    constructor() {
        this.nodes = new vis.DataSet([]);
        this.edges = new vis.DataSet([]);
        this.nodesView = new vis.DataView(this.nodes, { filter: (n) => DataManager.filter(n) });

        this.container = document.getElementById('mynetwork');
        this.network = null;

        this.compositor = new Compositor();
    }

    init() {
        this.initGraph();
        this.initRenderers();
        this.initUI();

        // Start Flow
        this.checkSession();
    }

    checkSession() {
        Notifications.setStatus("CONNECTING...", "info");
        // Always enforce session selection on entry
        Modals.initSessionModal(() => this.startStreaming());
    }

    startStreaming() {
        this.socket = new SocketClient(
            (data) => this.handleData(data),
            (status, type) => Notifications.setStatus(status, type)
        );
        this.socket.connect();

        API.getConfig().then(cfg => {
            // Sync config
            if (cfg.persistenceEnabled !== undefined) {
                State.filters.persistFindings = cfg.persistenceEnabled;
                // HUD needs to update DOM, assuming init sets them
            }
        });
    }

    initGraph() {
        const data = { nodes: this.nodesView, edges: this.edges };

        this.network = new vis.Network(this.container, data, GraphConfig);

        // Init Context Menu
        this.contextMenu = new ContextMenu(this.network, this.nodes);
        this.contextMenu.init();

        this.network.on("click", (p) => {
            // Context menu close - handled by ContextMenu class globally now, 
            // but we need to handle Details Panel logic specific to App or HUD.

            // Click logic (Details panel)
            if (p.nodes.length > 0) {
                const nodeId = p.nodes[0];
                const node = this.nodes.get(nodeId);
                // Trigger detail view
                this.network.selectNodes([nodeId]);

                if (node) {
                    HUD.showDetails(node);
                }
            } else {
                // Clicked on empty space
                HUD.hideDetails();
            }
        });
    }

    handleContextAction(action, nodeId) {
        // Deprecated, logic moved to ContextMenu class
    }

    initRenderers() {
        this.compositor.addRenderer(new GridRenderer(this.network));
        this.compositor.addRenderer(new HeatmapRenderer(this.network, this.nodesView));
        this.compositor.addRenderer(new TrailsRenderer(this.network, () => this.nodesView.getIds()));
        this.compositor.start();
    }

    async initUI() {
        HUD.init((prop, val) => {
            // Refresh Callback
            if (prop === 'physics') {
                this.network.setOptions({ physics: { enabled: val } });
            } else {
                this.nodesView.refresh();
            }
        });

        // Initialize FilterUI with nodes dataset
        const { FilterUI } = await import('./ui/filter_ui.js');
        FilterUI.init((prop, val) => {
            // Filter refresh callback
            this.nodesView.refresh();

            // Update vendor dropdown periodically
            if (prop === 'vendor' || prop === 'channels' || !prop) {
                FilterUI.populateVendorDropdown();
                FilterUI.populateChannelDropdown();
            }
        }, this.nodes);

        // Populate vendor dropdown initially
        setTimeout(() => {
            FilterUI.populateVendorDropdown();
            FilterUI.populateChannelDropdown();
        }, 2000); // Wait for initial data

        // Initialize Deauth Controller
        this.deauthController = new DeauthController(API, State);

        // Add context menu item for deauth attack
        this.contextMenu.addAction('deauth', 'Deauth Attack', (nodeId) => {
            const node = this.nodes.get(nodeId);
            if (node && node.group === 'ap') {
                this.deauthController.openPanel(node.MAC);
            }
        });

        Modals.initChannelModal();
        this.initSpatialTilt();
    }

    initSpatialTilt() {
        // Spatial 3D Tilt Effect
        const container = document.getElementById('mynetwork');
        const heatmap = document.getElementById('heatmap-layer');
        const radar = document.getElementById('radar-layer');

        if (!container) return;

        document.addEventListener('mousemove', (e) => {
            const x = e.clientX / window.innerWidth;
            const y = e.clientY / window.innerHeight;

            // Subtle tilt: Reduced intensity
            const tiltX = (y - 0.5) * 1;
            const tiltY = (x - 0.5) * -1;

            const transform = `perspective(1000px) rotateX(${tiltX}deg) rotateY(${tiltY}deg)`;

            container.style.transform = transform;
            if (heatmap) heatmap.style.transform = transform;
            if (radar) radar.style.transform = transform;
        });
    }

    handleData(data) {
        // Stats
        const apCount = data.nodes.filter(n => n.group === 'ap').length;
        const staCount = data.nodes.filter(n => n.group === 'station').length;
        HUD.updateStats(apCount, staCount);

        // Process
        const processedNodes = DataManager.processNodes(data.nodes);
        const processedEdges = DataManager.processEdges(data.edges, this.nodes);

        // Update
        // Note: Vis.js is smart enough to update diffs if ID matches
        this.nodes.update(processedNodes);
        this.edges.update(processedEdges);
    }
}

// --- Startup Verification & Bootstrap ---

class StartupVerifier {
    static async verify() {
        // 1. Check for Critical DOM Elements
        const requiredIds = ['mynetwork', 'status', 'dynamic-island'];
        const missing = requiredIds.filter(id => !document.getElementById(id));
        if (missing.length > 0) {
            throw new Error(`Critical DOM elements missing: ${missing.join(', ')}`);
        }

        // 2. Check for External Dependencies (Vis.js)
        if (typeof window.vis === 'undefined') {
            throw new Error("Vis.js library failed to load. Please check your internet connection or CDN availability.");
        }

        return true;
    }

    static reportError(msg) {
        console.error("Startup Error:", msg);
        const statusEl = document.getElementById('status');
        const islandEl = document.getElementById('dynamic-island');

        if (statusEl) {
            statusEl.innerText = "SYSTEM ERROR";
            statusEl.style.color = "var(--danger-color)";
        }

        if (islandEl) {
            islandEl.style.borderColor = "var(--danger-color)";
        }

        // Show a more detailed alert if possible, or just replace the status text
        // For now, let's append a visible error message to the body for absolute clarity
        const errDiv = document.createElement('div');
        errDiv.style.position = 'fixed';
        errDiv.style.top = '50%';
        errDiv.style.left = '50%';
        errDiv.style.transform = 'translate(-50%, -50%)';
        errDiv.style.background = 'rgba(20, 0, 0, 0.95)';
        errDiv.style.border = '1px solid red';
        errDiv.style.padding = '20px';
        errDiv.style.color = '#ff4444';
        errDiv.style.zIndex = '9999';
        errDiv.style.fontFamily = 'monospace';
        errDiv.innerHTML = `<h3><u>INITIALIZATION FAILED</u></h3><p>${msg}</p>`;
        document.body.appendChild(errDiv);
    }
}


// Bootstrap with Safety Harness
document.addEventListener('DOMContentLoaded', async () => {
    try {
        await StartupVerifier.verify();

        // Initialize App
        window.wmapApp = new App();
        window.wmapApp.init();

    } catch (err) {
        StartupVerifier.reportError(err.message || err);
    }
});
