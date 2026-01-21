/**
 * WMAP Main Entry
 * Refactored to coordinate Managers (Data, UI, Socket).
 */

import { API } from './core/api.js';
import { SocketClient } from './core/socket.js';
import { Events, NodeGroups } from './core/constants.js';
import { EventBus } from './core/event_bus.js';
import { Store } from './core/store/store.js';
import { Actions } from './core/store/actions.js';

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
import { GraphConfig } from './ui/graph_config.js?v=2';
import { StartupVerifier } from './core/startup.js';
import { VulnerabilityPanel } from './ui/vulnerability_panel.js';
import { SaturationManager } from './core/saturation_manager.js';

// Vis.js Global
const vis = window.vis;

class App {
    constructor() {
        // 0. Initialize Store
        Store.init();

        // 1. Managers
        this.console = new ConsoleManager();
        this.dataManager = new DataManager();
        this.uiManager = new UIManager(API, this.console, this.dataManager);
        this.vulnPanel = new VulnerabilityPanel();

        // 2. Core Components
        this.container = document.getElementById('mynetwork');
        this.network = null;
        this.compositor = new Compositor();

        this.socket = null;
        this.initialDataLoaded = false;

        // 3. Performance Optimization
        this.pendingGraphUpdate = null;
        this.updateScheduled = false;
    }

    init() {
        SaturationManager.init();
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

        // --- ZOOM CONTROLS ---
        const btnZoomIn = document.getElementById('zoom-in');
        const btnZoomOut = document.getElementById('zoom-out');
        const btnZoomFit = document.getElementById('zoom-fit');

        if (btnZoomIn) {
            btnZoomIn.onclick = () => {
                const scale = this.network.getScale();
                this.network.moveTo({ scale: scale + 0.2, animation: { duration: 300 } });
            };
        }
        if (btnZoomOut) {
            btnZoomOut.onclick = () => {
                const scale = this.network.getScale();
                this.network.moveTo({ scale: scale - 0.2, animation: { duration: 300 } });
            };
        }
        if (btnZoomFit) {
            btnZoomFit.onclick = () => {
                this.network.fit({ animation: { duration: 500, easingFunction: 'easeInOutQuad' } });
            };
        }

        // Context Menu
        this.contextMenu = new ContextMenu(this.network, this.dataManager.nodes);
        this.contextMenu.init();

        // Interaction Events - Optimized to avoid mass updates
        this.network.on("click", (p) => {
            if (p.nodes.length > 0) {
                const nodeId = p.nodes[0];
                const node = this.dataManager.nodes.get(nodeId);

                // Use Vis.js built-in selection highlighting (much more efficient)
                this.network.selectNodes([nodeId]);

                if (node) {
                    HUD.showDetails(node);
                }
            } else {
                // Deselect all
                this.network.unselectAll();
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

        // --- Store Subscriptions (The new way) ---

        // 1. Graph Updates
        Store.subscribe(Actions.GRAPH_UPDATED, (payload) => {
            this.updateGraph(payload);
        });

        // 2. Logging
        Store.subscribe(Actions.LOG_RECEIVED, (payload) => {
            this.console.log(payload.message, payload.level);
            // Legacy EventBus support for other components
            EventBus.emit(Events.LOG, payload);
        });

        // 3. Alerts
        Store.subscribe(Actions.ALERT_RECEIVED, (payload) => {
            this.handleAlert(payload);
        });

        // 4. Socket Status
        Store.subscribe(Actions.SOCKET_CONNECTING, () => {
            Notifications.setStatus("CONNECTING...", "info");
        });
        Store.subscribe(Actions.SOCKET_CONNECTED, () => {
            Notifications.setStatus("CONNECTED", "success");
            this.console.log("Socket Connected", "success");
        });
        Store.subscribe(Actions.SOCKET_DISCONNECTED, () => {
            Notifications.setStatus("DISCONNECTED", "danger");
            this.console.log("Socket Disconnected", "danger");
        });

        // 5. Specialized Events
        Store.subscribe(Actions.WPS_LOG_RECEIVED, (payload) => EventBus.emit('wps:log', payload));
        Store.subscribe(Actions.WPS_STATUS_UPDATED, (payload) => EventBus.emit('wps:status', payload));
        Store.subscribe(Actions.VULNERABILITY_DETECTED, (payload) => EventBus.emit('vulnerability:new', payload));


        // --- EventBus (The legacy way - kept for internals) ---

        // Graph Refresh
        EventBus.on('graph:refresh', () => this.dataManager.refreshView());

        // UI Physics Toggle
        EventBus.on('ui:physics', (enabled) => {
            this.network.setOptions({ physics: { enabled } });
        });

        // UI Force Stabilize
        EventBus.on('ui:stabilize', () => {
            if (this.network) {
                this.network.stabilize(500); // Run up to 500 iterations
            }
        });

        // UI Compositor Refresh
        EventBus.on('ui:refresh_compositor', () => {
            this.compositor.refresh();
        });

        // Initialize FilterUI listeners (lazy load handling)
        this.initFilterEvents();

        // Vuln Panel Toggle
        const vulnBtn = document.getElementById('btn-show-vulns');
        if (vulnBtn) {
            vulnBtn.onclick = () => this.vulnPanel.toggle();
        }
    }

    async initFilterEvents() {
        console.log("[Debug] initFilterEvents started");
        // Remove cache buster if not strictly meant for hot-reload dev, or keep it but store reference.
        // We stick to the pattern but ensure we store the instance.
        const module = await import('./ui/filter_ui.js?v=' + Date.now());
        this.filterUI = module.FilterUI;
        console.log("[Debug] FilterUI imported");

        this.filterUI.init(this.dataManager.nodes);
        console.log("[Debug] FilterUI.init called");

        EventBus.on(Events.SEARCH, () => this.dataManager.refreshView());
        EventBus.on(Events.VENDOR, () => {
            if (this.filterUI) this.filterUI.populateVendorDropdown();
            this.dataManager.refreshView();
        });
        EventBus.on(Events.CHANNELS, () => {
            if (this.filterUI) this.filterUI.populateChannelDropdown();
            this.dataManager.refreshView();
        });
    }

    checkWorkspace() {
        Notifications.setStatus("CONNECTING...", "info");
        Modals.initWorkspaceModal(() => this.startStreaming());
    }

    startStreaming() {
        // Initialize Socket (it will dispatch actions to Store)
        this.socket = new SocketClient();
        this.socket.connect();

        API.getConfig().then(cfg => {
            if (cfg.persistenceEnabled !== undefined) {
                Store.dispatch(Actions.FILTER_UPDATED, { key: 'persistFindings', value: cfg.persistenceEnabled });
            }
        });
    }

    updateGraph(payload) {
        // Store the latest update
        this.pendingGraphUpdate = payload;

        // Schedule update using requestAnimationFrame (throttle to 60fps)
        if (!this.updateScheduled) {
            this.updateScheduled = true;
            requestAnimationFrame(() => {
                this.processGraphUpdate();
                this.updateScheduled = false;
            });
        }
    }

    processGraphUpdate() {
        if (!this.pendingGraphUpdate) return;

        const payload = this.pendingGraphUpdate;
        this.pendingGraphUpdate = null;

        // Update Data
        this.dataManager.update(payload);

        // Update Stats
        const stats = this.dataManager.getStats();
        HUD.updateStats(stats.apCount, stats.staCount);

        // Update Vulnerability Panel
        // this.vulnPanel.render(this.dataManager.nodes.get()); // DEPRECATED: V2 pulls from API

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

        if (this.filterUI) {
            this.filterUI.populateVendorDropdown();
            this.filterUI.populateChannelDropdown();
        }

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
