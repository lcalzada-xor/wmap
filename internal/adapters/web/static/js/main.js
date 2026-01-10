/**
 * WMAP Main Entry
 * Refactored to coordinate Managers (Data, UI, Socket).
 */

import { API } from './core/api.js';
import { State } from './core/state.js';
import { SocketClient } from './core/socket.js';
import { Events, NodeGroups } from './core/constants.js';
import { EventBus } from './core/event_bus.js';

import { DataManager } from './core/data_manager.js';
import { UIManager } from './ui/ui_manager.js';

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
import { StartupVerifier } from './core/startup.js';

// Vis.js Global
const vis = window.vis;

class App {
    constructor() {
        // 1. Managers
        this.console = new ConsoleManager();
        this.dataManager = new DataManager();
        this.uiManager = new UIManager(API, this.console, this.dataManager);

        // 2. Core Components
        this.container = document.getElementById('mynetwork');
        this.network = null;
        this.compositor = new Compositor();

        this.socket = null;
        this.initialDataLoaded = false;
    }

    init() {
        this.initGraph();
        this.initRenderers();

        // Initialize UI Manager (Controllers, DOM, Events)
        // Pass contextMenu created in initGraph
        this.uiManager.init(this.contextMenu).then(() => {
            this.bindAppEvents();
        });

        this.console.init();

        // Verify authentication
        this.loadUser().then(() => {
            this.checkWorkspace();
            this.console.log("WMAP Kernel Initialized", "system");
        }).catch((error) => {
            console.error("Auth failed:", error);
            // Redirect handled by API
        });
    }

    initGraph() {
        const data = { nodes: this.dataManager.nodesView, edges: this.dataManager.edges };
        this.network = new vis.Network(this.container, data, GraphConfig);

        // Context Menu
        this.contextMenu = new ContextMenu(this.network, this.dataManager.nodes);
        this.contextMenu.init();

        // Interaction Events
        this.network.on("click", (p) => {
            if (p.nodes.length > 0) {
                const nodeId = p.nodes[0];
                const node = this.dataManager.nodes.get(nodeId);
                this.network.selectNodes([nodeId]);
                if (node) {
                    HUD.showDetails(node);
                }
            } else {
                HUD.hideDetails();
            }
        });
    }

    initRenderers() {
        this.compositor.addRenderer(new GridRenderer(this.network));
        this.compositor.addRenderer(new HeatmapRenderer(this.network, this.dataManager.nodesView));
        this.compositor.addRenderer(new TrailsRenderer(this.network, () => this.dataManager.nodesView.getIds()));
        this.compositor.start();
    }

    bindAppEvents() {
        // App-level event handling bridging Managers

        // Graph Refresh
        EventBus.on('graph:refresh', () => this.dataManager.refreshView());

        // UI Physics Toggle
        EventBus.on('ui:physics', (enabled) => {
            this.network.setOptions({ physics: { enabled } });
        });

        // UI Compositor Refresh
        EventBus.on('ui:refresh_compositor', () => {
            this.compositor.refresh();
        });

        // Initialize FilterUI listeners (lazy load handling)
        this.initFilterEvents();
    }

    async initFilterEvents() {
        const { FilterUI } = await import('./ui/filter_ui.js');
        FilterUI.init(this.dataManager.nodes);

        EventBus.on(Events.SEARCH, () => this.dataManager.refreshView());
        EventBus.on(Events.VENDOR, () => {
            FilterUI.populateVendorDropdown();
            this.dataManager.refreshView();
        });
        EventBus.on(Events.CHANNELS, () => {
            FilterUI.populateChannelDropdown();
            this.dataManager.refreshView();
        });
    }

    checkWorkspace() {
        Notifications.setStatus("CONNECTING...", "info");
        Modals.initWorkspaceModal(() => this.startStreaming());
    }

    startStreaming() {
        this.socket = new SocketClient(
            (data) => this.handleSocketData(data),
            (status, type) => {
                Notifications.setStatus(status, type);
                this.console.log(`Socket Status: ${status}`, type === 'danger' ? 'danger' : 'info');
            }
        );
        this.socket.connect();

        API.getConfig().then(cfg => {
            if (cfg.persistenceEnabled !== undefined) {
                State.filters.persistFindings = cfg.persistenceEnabled;
            }
        });
    }

    handleSocketData(msg) {
        let payload = msg;
        let type = 'graph';

        if (msg.type && msg.payload) {
            type = msg.type;
            payload = msg.payload;
        } else if (msg.nodes && msg.edges) {
            type = 'graph';
        }

        switch (type) {
            case 'log':
                this.console.log(payload.message, payload.level);
                EventBus.emit(Events.LOG, payload);
                break;
            case 'graph':
                this.updateGraph(payload);
                break;
            case 'alert':
                this.handleAlert(payload);
                break;
            case 'wps.log':
                EventBus.emit('wps:log', payload);
                break;
            case 'wps.status':
                EventBus.emit('wps:status', payload);
                break;
            default:
                console.warn("Unknown WS message:", msg);
        }
    }

    updateGraph(payload) {
        // Update Data
        this.dataManager.update(payload);

        // Update Stats
        const stats = this.dataManager.getStats();
        HUD.updateStats(stats.apCount, stats.staCount);

        // Initial Load Hook
        if (!this.initialDataLoaded && payload.nodes.length > 0) {
            this.initialDataLoaded = true;
            this.onInitialData();
        }
    }

    handleAlert(alert) {
        if (alert.type === 'HANDSHAKE_CAPTURED') {
            Notifications.show(`Handshake Captured! ${alert.details}`, 'warning');
            this.console.log(`[HANDSHAKE] Captured for ${alert.details}`, "warning");
        } else if (alert.type === 'ANOMALY') {
            Notifications.show(`${alert.message}`, 'danger');
            this.console.log(`[SECURITY] ${alert.message}`, "danger");
        } else {
            Notifications.show(`Alert: ${alert.message}`, 'info');
        }
    }

    async loadUser() {
        try {
            const user = await API.getMe();
            this.uiManager.updateUserUI(user);
        } catch (err) {
            console.error("Failed to load user", err);
        }
    }

    async onInitialData() {
        this.console.log("Initial Graph Data Received. Hydrating UI...", "system");

        const { FilterUI } = await import('./ui/filter_ui.js');
        FilterUI.populateVendorDropdown();
        FilterUI.populateChannelDropdown();

        EventBus.emit('graph:refresh');
    }
}

// Bootstrap
document.addEventListener('DOMContentLoaded', async () => {
    try {
        await StartupVerifier.verify();
        window.wmapApp = new App();
        window.wmapApp.init();
    } catch (err) {
        StartupVerifier.reportError(err.message || err);
    }
});
