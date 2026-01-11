import { Notifications } from './notifications.js';

export class AuthFloodController {
    constructor(apiClient, consoleManager = null) {
        this.apiClient = apiClient;
        this.console = consoleManager;
        this.panel = document.getElementById('auth-flood-panel');
        this.targetInput = document.getElementById('auth-flood-target');
        this.channelInput = document.getElementById('auth-flood-channel');

        this.activeAttackId = null;
        this.pollInterval = null;

        this.init();
    }

    init() {
        // Close button
        document.getElementById('btn-close-auth-flood')?.addEventListener('click', () => {
            this.closePanel();
        });

        // Toggle button (Sidebar)
        document.getElementById('btn-toggle-auth-flood')?.addEventListener('click', () => {
            this.togglePanel();
        });

        // Start attack button
        document.getElementById('btn-start-auth-flood')?.addEventListener('click', () => {
            this.startAttack();
        });

        // Stop attack button
        document.getElementById('btn-stop-auth-flood')?.addEventListener('click', () => {
            this.stopAttack();
        });
    }

    openPanel(bssid, channel) {
        this.panel.classList.add('active');
        if (bssid) this.targetInput.value = bssid;
        if (channel) this.channelInput.value = channel;
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

    log(msg, type = "info") {
        this.console?.log(`[MDK] ${msg}`, type);
    }

    async startAttack() {
        if (this.activeAttackId) {
            Notifications.show("Attack already running", "warning");
            return;
        }

        const bssid = this.targetInput.value;
        const channel = parseInt(this.channelInput.value) || 0;
        const packetCount = parseInt(document.getElementById('auth-flood-count').value) || 0;

        if (!bssid) {
            Notifications.show("Target BSSID is required", "warning");
            return;
        }

        this.log(`Starting Auth Flood on ${bssid}...`, "info");

        const config = {
            target_bssid: bssid,
            channel: channel,
            packet_count: packetCount,
            packet_interval_ms: 10, // Fast default
            interface: '' // Auto
        };

        try {
            const resp = await this.apiClient.request('/api/attack/auth-flood/start', {
                method: 'POST',
                body: JSON.stringify(config)
            });

            this.activeAttackId = resp.attack_id;
            this.log(`Attack Started! ID: ${this.activeAttackId}`, "success");
            Notifications.show("Auth Flood Started", "success");

            this.updateUIState(true);
            this.startPolling();

        } catch (error) {
            console.error("Auth Flood Failed:", error);
            this.log(`Failed: ${error.message}`, "danger");
            Notifications.show(`Failed: ${error.message}`, "danger");
        }
    }

    async stopAttack() {
        if (!this.activeAttackId) return;

        try {
            await this.apiClient.request(`/api/attack/auth-flood/stop?id=${this.activeAttackId}`, {
                method: 'POST'
            });
            this.log("Attack stopped", "info");
            Notifications.show("Auth Flood Stopped", "info");
        } catch (error) {
            console.error("Stop failed:", error);
            this.log("Failed to stop attack", "danger");
        } finally {
            this.cleanup();
        }
    }

    startPolling() {
        if (this.pollInterval) clearInterval(this.pollInterval);
        this.pollInterval = setInterval(async () => {
            if (!this.activeAttackId) return;

            try {
                const status = await this.apiClient.request(`/api/attack/auth-flood/status?id=${this.activeAttackId}`, {
                    method: 'GET'
                });

                document.getElementById('auth-flood-status-text').innerText = status.status;
                document.getElementById('auth-flood-packets').innerText = status.packets_sent;

                if (status.status !== 'running') {
                    this.cleanup();
                }
            } catch (err) {
                // Attack likely invalid or finished
                this.cleanup();
            }
        }, 1000);
    }

    cleanup() {
        this.activeAttackId = null;
        if (this.pollInterval) clearInterval(this.pollInterval);
        this.updateUIState(false);
        document.getElementById('auth-flood-status-text').innerText = "Ready";
    }

    updateUIState(isRunning) {
        const startBtn = document.getElementById('btn-start-auth-flood');
        const stopBtn = document.getElementById('btn-stop-auth-flood');

        if (isRunning) {
            startBtn.style.display = 'none';
            stopBtn.style.display = 'block';
            this.panel.classList.add('attack-running');
        } else {
            startBtn.style.display = 'block';
            stopBtn.style.display = 'none';
            this.panel.classList.remove('attack-running');
        }
    }
}
