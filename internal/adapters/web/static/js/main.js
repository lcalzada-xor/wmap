/**
 * WMAP Main Entry
 */

import { API } from './core/api.js';
import { State } from './core/state.js';
import { SocketClient } from './core/socket.js';
import { NodeGroups, Events } from './core/constants.js';

import { DataManager } from './graph/data.js';

import { Compositor } from './render/compositor.js';
import { GridRenderer } from './render/grid.js';
import { HeatmapRenderer } from './render/heatmap.js';
import { TrailsRenderer } from './render/trails.js';

import { Notifications } from './ui/notifications.js';
import { Modals } from './ui/modals.js';
import { HUD } from './ui/hud.js';
import { ConsoleManager } from './ui/console.js';

import { ContextMenu } from './ui/context_menu.js';
import { GraphConfig } from './ui/graph_config.js';
import { DeauthController } from './ui/deauth_controller.js';
import { StartupVerifier } from './core/startup.js';

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

        // Console Manager
        this.console = new ConsoleManager();
    }

    init() {
        this.initGraph();
        this.initRenderers();
        this.initUI();

        // Start Flow
        this.checkSession();

        // Initial System Log
        this.console.log("WMAP Kernel Initialized", "system");
    }

    checkSession() {
        Notifications.setStatus("CONNECTING...", "info");
        // Always enforce session selection on entry
        Modals.initSessionModal(() => this.startStreaming());
    }

    startStreaming() {
        this.socket = new SocketClient(
            (data) => this.handleData(data),
            (status, type) => {
                Notifications.setStatus(status, type);
                this.console.log(`Socket Status: ${status}`, type === 'danger' ? 'danger' : 'info');
            }
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
        // Initialize Console
        this.console.init();

        // Expose globally for convenience (and for other modules to log)
        window.Console = this.console;

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
            if (prop === Events.VENDOR || prop === Events.CHANNELS || !prop) {
                FilterUI.populateVendorDropdown();
                FilterUI.populateChannelDropdown();
            }
        }, this.nodes);

        // Populate initially only when we have data - Moved to handleData


        // Initialize Deauth Controller
        try {
            this.deauthController = new DeauthController(API, this.nodes);

            // Add context menu item for deauth attack
            this.contextMenu.addAction('deauth', 'Deauth Attack', (nodeId) => {
                const node = this.nodes.get(nodeId);
                if (node) {
                    const group = (node.group || '').toLowerCase();

                    if (group === NodeGroups.AP || group === NodeGroups.ACCESS_POINT) {
                        // Target is AP
                        this.deauthController.openPanel(node.mac);
                        this.console.log(`Deauth panel opened for AP: ${node.mac}`, "warning");
                    } else if (group === NodeGroups.STATION || group === NodeGroups.CLIENT || group === NodeGroups.STA) {
                        // Target is Client (Station)
                        // Try to find connected AP
                        let connectedAP = null;
                        const connectedIds = this.network.getConnectedNodes(nodeId);

                        if (connectedIds && connectedIds.length > 0) {
                            for (const cid of connectedIds) {
                                const cNode = this.nodes.get(cid);
                                if (cNode && (cNode.group === NodeGroups.AP || cNode.group === NodeGroups.ACCESS_POINT)) {
                                    connectedAP = cNode.mac; // Use lowercase mac
                                    break;
                                }
                            }
                        }

                        this.deauthController.openPanel(connectedAP, node.mac);
                        this.console.log(`Deauth panel opened for Station: ${node.mac} (Linked AP: ${connectedAP || 'None'})`, "warning");
                    } else {
                        this.console.log(`Deauth not available for node type: ${node.group}`, "info");
                    }
                }
            });
        } catch (err) {
            console.error("Failed to initialize DeauthController", err);
            this.console.log("Deauth Module Failed: " + err.message, "danger");
        }

        try {
            Modals.initChannelModal();
        } catch (err) {
            console.error("Failed to initialize ChannelModal", err);
        }

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

    handleData(msg) {
        // Handle new envelope format
        let payload = msg;
        let type = 'graph'; // Assume graph if no type (legacy/fallback)

        if (msg.type && msg.payload) {
            type = msg.type;
            payload = msg.payload;
        } else if (msg.nodes && msg.edges) {
            // direct graph data
            type = 'graph';
        }

        switch (type) {
            case 'log':
                this.console.log(payload.message, payload.level);
                break;
            case 'graph':
                this.updateGraph(payload);
                break;
            default:
                console.warn("Unknown WS message:", msg);
        }
    }

    updateGraph(data) {
        // Stats
        const apCount = data.nodes.filter(n => n.group === NodeGroups.AP).length;
        const staCount = data.nodes.filter(n => n.group === NodeGroups.STATION).length;
        HUD.updateStats(apCount, staCount);

        // Process
        const processedNodes = DataManager.processNodes(data.nodes);
        const processedEdges = DataManager.processEdges(data.edges, this.nodes);

        // Update
        // Note: Vis.js is smart enough to update diffs if ID matches
        this.nodes.update(processedNodes);
        this.edges.update(processedEdges);

        // Initial Data Hook
        if (!this.initialDataLoaded && data.nodes.length > 0) {
            this.initialDataLoaded = true;
            this.onInitialData();
        }
    }

    async onInitialData() {
        this.console.log("Initial Graph Data Received. Hydrating UI...", "system");

        // Lazy load FilterUI if not already (it should be init by now but safe to check)
        // We can access the module via the instance if we stored it, 
        // OR re-import since ES modules are cached.
        const { FilterUI } = await import('./ui/filter_ui.js');

        FilterUI.populateVendorDropdown();
        FilterUI.populateChannelDropdown();
    }
}

// --- Startup Verification & Bootstrap ---

// --- Startup Verification & Bootstrap ---

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
