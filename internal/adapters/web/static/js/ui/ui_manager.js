/**
 * UI Manager
 * Handles DOM bindings, Event Listeners, and UI Controller initialization.
 */

import { API } from '../core/api.js';
import { HUD } from './hud.js';
import { Notifications } from './notifications.js';
import { Modals } from './modals.js';
import { ConsoleManager } from './console.js'; // Helper, though Main Console is passed
import { EventBus } from '../core/event_bus.js';
import { Events } from '../core/constants.js';

import { DeauthController } from './deauth_controller.js';
import { WPSController } from './wps_controller.js';
import { AuthFloodController } from './auth_flood_controller.js';
import { ReportModal } from './report_modal.js';
import HealthUI from './health_ui.js';

export class UIManager {
    constructor(api, consoleManager, dataManager) {
        this.api = api;
        this.console = consoleManager;
        this.data = dataManager; // Access to nodes/edges if needed by controllers

        // Controllers
        this.deauthController = null;
        this.wpsController = null;
        this.authFloodController = null;
        this.healthUI = null;
        this.auditManager = null;
        this.contextMenu = null;
        this.reportModal = null;
    }

    async init(contextMenu) {
        this.contextMenu = contextMenu;

        // Initialize basic UI components
        this.initHUD();

        await this.initControllers();
        this.initDOMBindings();
        this.initSpatialTilt(); // Purely visual

        // Listen for EventBus events that affect UI
        this.bindEvents();
    }

    initHUD() {
        // Initialize HUD with refresh callbacks and action callbacks
        // Note: The actual refresh logic relies on the App/Compositor, 
        // so we might need to emit events or call back to App. 
        // For now, we'll emit events on EventBus which App/Compositor listens to.

        HUD.init(
            (prop, val) => {
                // Determine event based on prop
                if (prop === 'physics') {
                    EventBus.emit('ui:physics', val);
                } else if (prop === 'stabilize') {
                    EventBus.emit('ui:stabilize');
                } else if (prop === 'grid' || prop === 'trails' || prop === 'heatmap') {
                    EventBus.emit('ui:render_layer', { layer: prop, enabled: val }); // val isn't passed for refresh but let's assume toggle
                    // Actually original code was: props === 'grid' ... -> compositor.refresh()
                    // So just emit 'ui:refresh_compositor'
                    EventBus.emit('ui:refresh_compositor');
                } else if (prop === 'clear') {
                    this.data.clear(); // Call DataManager directly
                }
                // Always refresh graph view
                EventBus.emit('graph:refresh');
            },
            (action, data) => this.handleHUDAction(action, data)
        );
        window.HUD = HUD; // Legacy support
    }

    async initControllers() {
        // 1. Deauth Controller
        try {
            this.deauthController = new DeauthController(this.api, this.data.nodes, this.console);
            // Register Context Menu Action
            this.contextMenu.addAction('deauth', 'Deauth Attack', (nodeId) => {
                const node = this.data.nodes.get(nodeId);
                if (node) {
                    if (this.isRestricted()) return;
                    this.deauthController.openPanel(node.mac, null, node.channel);
                }
            });
        } catch (err) {
            console.error("Failed to initialize DeauthController", err);
            this.console.log("Deauth Module Failed: " + err.message, "danger");
        }

        // 2. WPS Controller
        try {
            this.wpsController = new WPSController(this.api, this.console);
            this.contextMenu.addAction('wps-attack', 'Pixie Dust Attack', (nodeId) => {
                const node = this.data.nodes.get(nodeId);
                if (node) {
                    if (this.isRestricted()) return;
                    this.handleHUDAction('wps-attack', { mac: node.mac, ssid: node.ssid, channel: node.channel });
                }
            });
        } catch (err) {
            console.error("Failed to initialize WPSController", err);
            this.console.log("WPS Module Failed: " + err.message, "danger");
        }

        // 3. Auth Flood Controller
        try {
            this.authFloodController = new AuthFloodController(this.api, this.console);
        } catch (err) {
            console.error("Failed to initialize AuthFloodController", err);
        }

        // 4. Audit Manager
        try {
            const { AuditManager } = await import('./audit_manager.js');
            this.auditManager = new AuditManager();
        } catch (err) {
            console.error("Failed to initialize AuditManager", err);
        }

        // 5. Report Modal
        try {
            this.reportModal = new ReportModal();
        } catch (err) {
            console.error("Failed to initialize ReportModal", err);
        }

        // 6. Modals
        try {
            Modals.initChannelModal();
        } catch (err) {
            console.error("Failed to initialize ChannelModal", err);
        }
    }

    initDOMBindings() {
        // Report Export - Open Modal
        const btnExport = document.getElementById('btn-export-report');
        if (btnExport) {
            btnExport.onclick = () => {
                if (this.reportModal) {
                    this.reportModal.open();
                } else {
                    console.error('Report modal not initialized');
                }
            };
        }


        // Health UI
        this.healthUI = new HealthUI();
        const btnHealth = document.getElementById('btn-health-monitor');
        if (btnHealth) {
            btnHealth.onclick = () => this.healthUI.open();
        }

        // Logout
        const btnLogout = document.getElementById('btn-logout');
        if (btnLogout) {
            btnLogout.onclick = async () => {
                try {
                    await this.api.request('/api/logout', { method: 'POST' });
                    window.location.href = '/login.html';
                } catch (err) {
                    console.error("Logout failed", err);
                    Notifications.show("Logout failed", "danger");
                }
            };
        }
    }

    handleHUDAction(action, data) {
        if (action === 'wps-attack') {
            if (this.wpsController) {
                this.wpsController.openPanel(data.mac, data.ssid, parseInt(data.channel));
            } else {
                console.error("WPS Controller not initialized");
            }
        } else if (action === 'open-handshakes') {
            window.open('file:///home/llvch/.local/share/wmap/handshakes', '_blank');
        }
    }

    isRestricted() {
        if (this.currentUser && this.currentUser.role === 'viewer') {
            Notifications.show("Restricted: Operators only.", "warning");
            return true;
        }
        return false;
    }

    updateUserUI(user) {
        this.currentUser = user;
        const el = document.getElementById('username-display');
        if (el) el.innerText = user.username.toUpperCase();

        if (user.role === 'viewer') {
            const deauthBtn = document.getElementById('btn-toggle-deauth');
            if (deauthBtn) {
                deauthBtn.style.opacity = '0.5';
                deauthBtn.style.pointerEvents = 'none';
                deauthBtn.title = 'Available for Operators only';
            }
        }
    }

    initSpatialTilt() {
        const container = document.getElementById('mynetwork');
        if (!container) return;

        const heatmap = document.getElementById('heatmap-layer');
        const radar = document.getElementById('radar-layer');

        document.addEventListener('mousemove', (e) => {
            const x = e.clientX / window.innerWidth;
            const y = e.clientY / window.innerHeight;
            const tiltX = (y - 0.5) * 1;
            const tiltY = (x - 0.5) * -1;
            const transform = `perspective(1000px) rotateX(${tiltX}deg) rotateY(${tiltY}deg)`;

            container.style.transform = transform;
            if (heatmap) heatmap.style.transform = transform;
            if (radar) radar.style.transform = transform;
        });
    }

    bindEvents() {
        // Any UI specific event bindings
    }
}
