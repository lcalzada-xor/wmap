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

        // Attack Type Toggle (Auth vs Assoc)
        const typeSelect = document.getElementById('auth-flood-type');
        const ssidGroup = document.getElementById('auth-flood-ssid-group');
        typeSelect?.addEventListener('change', (e) => {
            if (e.target.value === 'assoc') {
                ssidGroup.style.display = 'block';
            } else {
                ssidGroup.style.display = 'none';
            }
        });

        // MAC Mode Toggle (Random vs Fixed)
        const macRadios = document.getElementsByName('auth-flood-mac-mode');
        const fixedMacInput = document.getElementById('auth-flood-fixed-mac');
        macRadios.forEach(radio => {
            radio.addEventListener('change', (e) => {
                if (e.target.value === 'fixed') {
                    fixedMacInput.disabled = false;
                    fixedMacInput.focus();
                } else {
                    fixedMacInput.disabled = true;
                    fixedMacInput.value = '';
                }
            });
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

        // New Inputs
        const attackType = document.getElementById('auth-flood-type').value;
        const targetSSID = document.getElementById('auth-flood-ssid').value;
        const intervalMs = parseInt(document.getElementById('auth-flood-interval').value) || 10;

        let useRandomMac = true;
        const macMode = document.querySelector('input[name="auth-flood-mac-mode"]:checked')?.value;
        const fixedSourceMac = document.getElementById('auth-flood-fixed-mac').value;

        if (macMode === 'fixed') {
            useRandomMac = false;
        }

        if (!bssid) {
            Notifications.show("Target BSSID is required", "warning");
            return;
        }

        if (attackType === 'assoc' && !targetSSID) {
            Notifications.show("Target SSID is required for Association Flood", "warning");
            return;
        }

        if (!useRandomMac && !fixedSourceMac) {
            Notifications.show("Fixed MAC Address is required", "warning");
            return;
        }

        this.log(`Starting ${attackType.toUpperCase()} Flood on ${bssid}...`, "info");

        const config = {
            target_bssid: bssid,
            channel: channel,
            packet_count: packetCount,
            packet_interval_ms: intervalMs,
            interface: '', // Auto

            // New Config
            attack_type: attackType,
            target_ssid: targetSSID,
            use_random_mac: useRandomMac,
            fixed_source_mac: fixedSourceMac
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
