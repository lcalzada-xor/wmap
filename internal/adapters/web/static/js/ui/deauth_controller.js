// DeauthController - Manages deauth attack panel and operations
export class DeauthController {
    constructor(apiClient, state) {
        this.apiClient = apiClient;
        this.state = state;
        this.panel = document.getElementById('deauth-panel');
        this.targetSelect = document.getElementById('deauth-target');
        this.attackList = document.getElementById('attack-list');
        this.activeAttacks = new Map();
        this.updateInterval = null;

        this.init();
    }

    init() {
        // Close button
        document.getElementById('btn-close-deauth')?.addEventListener('click', () => {
            this.closePanel();
        });

        // Start attack button
        document.getElementById('start-deauth-btn')?.addEventListener('click', () => {
            this.startAttack();
        });

        // Update target dropdown when state changes
        this.state.on('graphUpdated', () => {
            this.updateTargetDropdown();
        });

        // Start periodic updates
        this.startPeriodicUpdates();
    }

    openPanel(targetMAC = null) {
        this.panel.classList.add('active');
        this.updateTargetDropdown();

        if (targetMAC) {
            this.targetSelect.value = targetMAC;
        }
    }

    closePanel() {
        this.panel.classList.remove('active');
    }

    updateTargetDropdown() {
        const graphData = this.state.getGraphData();
        if (!graphData || !graphData.nodes) return;

        // Clear existing options except the first one
        this.targetSelect.innerHTML = '<option value="">-- Select Target --</option>';

        // Add AP nodes as options
        graphData.nodes
            .filter(node => node.group === 'ap')
            .forEach(node => {
                const option = document.createElement('option');
                option.value = node.MAC;
                option.textContent = `${node.label || node.MAC} (${node.MAC})`;
                this.targetSelect.appendChild(option);
            });
    }

    async startAttack() {
        const targetMAC = this.targetSelect.value;
        const attackType = document.getElementById('deauth-type').value;
        const clientMAC = document.getElementById('deauth-client-mac').value;
        const packetCount = parseInt(document.getElementById('deauth-count').value);
        const packetInterval = parseInt(document.getElementById('deauth-interval').value);
        const reasonCode = parseInt(document.getElementById('deauth-reason').value);
        const legalAck = document.getElementById('deauth-legal-ack').checked;

        // Validation
        if (!targetMAC) {
            this.showNotification('Please select a target device', 'warning');
            return;
        }

        if (!legalAck) {
            this.showNotification('Legal acknowledgment required', 'danger');
            return;
        }

        if ((attackType === 'unicast' || attackType === 'targeted') && !clientMAC) {
            this.showNotification('Client MAC required for this attack type', 'warning');
            return;
        }

        // Prepare attack config
        const config = {
            target_mac: targetMAC,
            client_mac: clientMAC || undefined,
            attack_type: attackType,
            packet_count: packetCount,
            packet_interval_ms: packetInterval,
            reason_code: reasonCode,
            channel: 0, // Auto-detect from target
            legal_acknowledgment: legalAck
        };

        try {
            const response = await fetch('/api/deauth/start', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(config)
            });

            if (!response.ok) {
                const error = await response.text();
                throw new Error(error);
            }

            const result = await response.json();
            this.showNotification(`Attack started: ${result.attack_id}`, 'success');

            // Add to active attacks
            this.activeAttacks.set(result.attack_id, {
                id: result.attack_id,
                config: config,
                status: 'running'
            });

            this.updateAttackList();
        } catch (error) {
            console.error('Failed to start attack:', error);
            this.showNotification(`Failed to start attack: ${error.message}`, 'danger');
        }
    }

    async stopAttack(attackId) {
        try {
            const response = await fetch(`/api/deauth/stop?id=${attackId}`, {
                method: 'POST'
            });

            if (!response.ok) {
                throw new Error('Failed to stop attack');
            }

            this.showNotification('Attack stopped', 'success');
            this.activeAttacks.delete(attackId);
            this.updateAttackList();
        } catch (error) {
            console.error('Failed to stop attack:', error);
            this.showNotification('Failed to stop attack', 'danger');
        }
    }

    async updateAttackList() {
        try {
            const response = await fetch('/api/deauth/list');
            if (!response.ok) return;

            const data = await response.json();
            const attacks = data.attacks || [];

            if (attacks.length === 0) {
                this.attackList.innerHTML = `
                    <div style="text-align: center; opacity: 0.6; padding: 20px; font-size: 0.85em;">
                        No active attacks
                    </div>
                `;
                return;
            }

            this.attackList.innerHTML = attacks.map(attack => this.renderAttackItem(attack)).join('');

            // Add event listeners to stop buttons
            this.attackList.querySelectorAll('.btn-stop-attack').forEach(btn => {
                btn.addEventListener('click', (e) => {
                    const attackId = e.target.dataset.attackId;
                    this.stopAttack(attackId);
                });
            });
        } catch (error) {
            console.error('Failed to update attack list:', error);
        }
    }

    renderAttackItem(attack) {
        const duration = attack.end_time
            ? this.formatDuration(new Date(attack.end_time) - new Date(attack.start_time))
            : this.formatDuration(Date.now() - new Date(attack.start_time).getTime());

        const statusClass = attack.status.toLowerCase();

        return `
            <div class="attack-item">
                <div class="attack-header">
                    <span class="attack-id">${attack.id.substring(0, 8)}...</span>
                    <span class="attack-status ${statusClass}">${attack.status}</span>
                </div>
                <div style="font-size: 0.85em; margin: 6px 0;">
                    <strong>Target:</strong> ${attack.config.target_mac}<br>
                    <strong>Type:</strong> ${attack.config.attack_type}
                </div>
                <div class="attack-metrics">
                    <span><i class="fas fa-paper-plane"></i> ${attack.packets_sent} packets</span>
                    <span><i class="fas fa-clock"></i> ${duration}</span>
                </div>
                ${attack.status === 'running' ? `
                    <div class="attack-controls">
                        <button class="btn-stop btn-stop-attack" data-attack-id="${attack.id}">
                            <i class="fas fa-stop"></i> Stop
                        </button>
                    </div>
                ` : ''}
            </div>
        `;
    }

    formatDuration(ms) {
        const seconds = Math.floor(ms / 1000);
        const minutes = Math.floor(seconds / 60);
        const hours = Math.floor(minutes / 60);

        if (hours > 0) {
            return `${hours}h ${minutes % 60}m`;
        } else if (minutes > 0) {
            return `${minutes}m ${seconds % 60}s`;
        } else {
            return `${seconds}s`;
        }
    }

    startPeriodicUpdates() {
        // Update attack list every 2 seconds
        this.updateInterval = setInterval(() => {
            if (this.panel.classList.contains('active')) {
                this.updateAttackList();
            }
        }, 2000);
    }

    showNotification(message, type = 'info') {
        // Use existing notification system
        if (window.notify) {
            window.notify(message, type);
        } else {
            console.log(`[${type.toUpperCase()}] ${message}`);
        }
    }

    destroy() {
        if (this.updateInterval) {
            clearInterval(this.updateInterval);
        }
    }
}
