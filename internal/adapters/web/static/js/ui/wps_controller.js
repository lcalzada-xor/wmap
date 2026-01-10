import { Notifications } from './notifications.js';
import { EventBus } from '../core/event_bus.js';

export class WPSController {
    constructor(apiClient, consoleManager = null) {
        this.apiClient = apiClient;
        this.console = consoleManager;
        this.panel = document.getElementById('wps-panel');
        this.targetInput = document.getElementById('wps-target');
        this.channelInput = document.getElementById('wps-channel');
        this.timeoutInput = document.getElementById('wps-timeout');
        this.statusList = document.getElementById('wps-status-list');
        this.activeAttacks = new Map();

        this.init();
    }

    init() {
        // Close button
        document.getElementById('btn-close-wps')?.addEventListener('click', () => {
            this.closePanel();
        });

        // Toggle button (Sidebar) handled by main/context menu logic usually, 
        // but we can bind if it exists static
        document.getElementById('btn-toggle-wps')?.addEventListener('click', () => {
            this.togglePanel();
        });

        // Start attack button
        document.getElementById('btn-start-wps')?.addEventListener('click', () => {
            this.startAttack();
        });

        // WebSocket Event Listeners
        EventBus.on('wps:log', (data) => {
            if (this.activeAttacks.has(data.attack_id)) {
                this.log(data.line, "info");
            }
        });

        EventBus.on('wps:status', (status) => {
            if (this.activeAttacks.has(status.id)) {
                this.handleStatusUpdate(status);
            }
        });
    }

    openPanel(bssid, ssid, channel) {
        this.panel.classList.add('active');

        if (bssid) this.targetInput.value = bssid;
        if (channel) this.channelInput.value = channel;
        // Reset timeout to default
        if (this.timeoutInput) this.timeoutInput.value = 120;

        // Clear previous status if empty
        if (this.activeAttacks.size === 0) {
            this.renderStatus("Ready to launch");
        }
    }

    closePanel() {
        this.panel.classList.remove('active');
    }

    togglePanel() {
        if (this.panel.classList.contains('active')) {
            this.closePanel();
        } else {
            this.openPanel();
        }
    }

    renderStatus(msg, type = "info") {
        let color = "#aaa";
        if (type === 'success') color = "var(--success-color)";
        if (type === 'danger') color = "var(--danger-color)";
        if (type === 'warning') color = "var(--warning-color)";

        this.statusList.innerHTML = `
            <div style="text-align: center; opacity: 0.8; padding: 20px; font-size: 0.85em; color: ${color}">
                ${msg}
            </div>
        `;
    }

    log(msg, type = "info") {
        this.console?.log(`[WPS] ${msg}`, type);
    }

    async startAttack() {
        const bssid = this.targetInput.value;
        const channel = this.channelInput.value;
        const timeout = parseInt(this.timeoutInput.value) || 120;

        if (!bssid) {
            Notifications.show("Target BSSID is required", "warning");
            return;
        }

        this.log(`Initiating attack on ${bssid} (Ch: ${channel})`, "info");
        Notifications.show(`Starting Pixie Dust Attack on ${bssid}...`, 'info');
        this.renderStatus(`<i class="fas fa-spinner fa-spin"></i> Attack Running...`, 'warning');

        const config = {
            target_bssid: bssid,
            channel: parseInt(channel) || 0,
            timeout_seconds: timeout,
            interface: '' // Backend auto-detect
        };

        try {
            const resp = await this.apiClient.request('/api/wps/start', {
                method: 'POST',
                body: JSON.stringify(config)
            });

            this.log(`Attack Started! ID: ${resp.id}`, "success");
            Notifications.show(`Attack Started! ID: ${resp.id}`, 'success');

            this.activeAttacks.set(resp.id, {
                status: 'running',
                target: bssid
            });

            this.activeAttacks.set(resp.id, {
                status: 'running',
                target: bssid
            });

            // No polling needed, using WebSockets
            // this.pollStatus(resp.id);

        } catch (error) {
            console.error("WPS Attack Failed:", error);
            this.log(`Attack Failed: ${error.message}`, "danger");
            Notifications.show(`Attack Failed: ${error.message}`, 'danger');
            this.renderStatus(`Failed: ${error.message}`, 'danger');
        }
    }

    handleStatusUpdate(status) {
        if (status.status === 'success') {
            this.finishAttack(status.id, 'success', status);
        } else if (['failed', 'timeout', 'stopped'].includes(status.status)) {
            this.finishAttack(status.id, 'error', status);
        } else {
            // Still running
            this.renderStatus(`<i class="fas fa-circle-notch fa-spin"></i> Running... <br><span style="font-size:0.8em; opacity:0.7">${status.status}</span>`, 'warning');
        }
    }

    finishAttack(id, outcome, status) {
        clearInterval(this.pollInterval);
        this.activeAttacks.delete(id);

        if (outcome === 'success') {
            let msg = `PIN FOUND: ${status.recovered_pin}`;
            if (status.recovered_psk) msg += `<br>PSK: ${status.recovered_psk}`;

            this.renderStatus(`<i class="fas fa-check-circle"></i> ${msg}`, 'success');
            Notifications.show(`WPS Success! PIN: ${status.recovered_pin}`, 'success', 10000);
            this.log(`SUCCESS: PIN: ${status.recovered_pin}`, "success");
        } else {
            const errorMsg = status.error_message || status.status;
            this.renderStatus(`<i class="fas fa-times-circle"></i> Attack Ended: ${status.status}`, 'danger');
            Notifications.show(`Attack Finished: ${status.status}`, outcome === 'error' ? 'danger' : 'warning');
            this.log(`Attack Ended: ${status.status} - ${errorMsg}`, "warning");
        }
    }
}
