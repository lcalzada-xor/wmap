import { NodeGroups } from '../core/constants.js';
import { Notifications } from './notifications.js';
import { DeauthTemplates } from './deauth_templates.js';

// DeauthController - Manages deauth attack panel and operations
export class DeauthController {
    constructor(apiClient, nodes, consoleManager = null) {
        this.apiClient = apiClient;
        this.nodes = nodes; // vis.DataSet
        this.console = consoleManager; // ConsoleManager instance
        this.panel = document.getElementById('deauth-panel');
        this.targetSelect = document.getElementById('deauth-target');
        this.interfaceSelect = document.getElementById('deauth-interface');
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

        // Toggle button (Sidebar)
        document.getElementById('btn-toggle-deauth')?.addEventListener('click', () => {
            this.togglePanel();
        });

        // Start attack button
        document.getElementById('start-deauth-btn')?.addEventListener('click', () => {
            this.startAttack();
        });

        // Update target dropdown when nodes change
        // Debounce slightly to avoid heavy re-rendering on high traffic
        let debounce = null;
        const debouncedUpdate = () => {
            if (debounce) clearTimeout(debounce);
            debounce = setTimeout(() => {
                this.updateTargetDropdown();
            }, 1000);
        };

        if (this.nodes) {
            this.nodes.on('*', debouncedUpdate);
        }

        // MitM Preset Button
        document.getElementById('mitm-prep-btn')?.addEventListener('click', () => {
            this.applyMitmPreset();
        });

        // Start periodic updates
        this.startPeriodicUpdates();
    }

    openPanel(targetMAC = null, clientMAC = null, channel = null) {
        this.panel.classList.add('active');
        this.updateTargetDropdown();
        this.populateInterfaces();

        if (targetMAC) {
            // Ensure the option exists before selecting
            let optionExists = false;
            for (let i = 0; i < this.targetSelect.options.length; i++) {
                if (this.targetSelect.options[i].value === targetMAC) {
                    optionExists = true;
                    break;
                }
            }

            if (!optionExists) {
                const node = this.nodes.get(targetMAC); // Try to get info
                // If we have the node, and channel wasn't passed, try to get it
                if (node && !channel && node.channel) {
                    channel = node.channel;
                }
                const label = node ? (node.ssid ? `${node.ssid} (${targetMAC})` : targetMAC) : targetMAC;
                const option = document.createElement('option');
                option.value = targetMAC;
                option.textContent = label;
                this.targetSelect.appendChild(option);
            } else if (!channel) {
                // If option exists but channel not passed, try to find it from nodes
                const node = this.nodes.get(targetMAC);
                if (node && node.channel) channel = node.channel;
            }

            this.targetSelect.value = targetMAC;
        }

        if (channel) {
            const channelInput = document.getElementById('deauth-channel');
            if (channelInput) {
                channelInput.value = channel;
                this.highlightField(channelInput);
            }
        }

        if (clientMAC) {
            const clientInput = document.getElementById('deauth-client-mac');
            const typeSelect = document.getElementById('deauth-type');

            if (clientInput) {
                clientInput.value = clientMAC;
                this.highlightField(clientInput);
            }

            if (typeSelect) {
                typeSelect.value = 'unicast';
                this.highlightField(typeSelect);
            }
        }
    }

    togglePanel() {
        if (this.panel.classList.contains('active')) {
            this.closePanel();
        } else {
            this.openPanel();
        }
    }

    closePanel() {
        this.panel.classList.remove('active');
    }

    async populateInterfaces() {
        if (!this.interfaceSelect) return;

        try {
            const data = await this.apiClient.getInterfaces();

            // Save current selection
            const currentSelection = this.interfaceSelect.value;

            this.interfaceSelect.innerHTML = '<option value="">Safe Default (Auto)</option>';

            if (data.interfaces && Array.isArray(data.interfaces)) {
                data.interfaces.forEach(iface => {
                    const option = document.createElement('option');
                    option.value = iface.name;
                    option.textContent = `${iface.name} (${iface.mac || 'Unknown MAC'})`;
                    this.interfaceSelect.appendChild(option);
                });
            }

            // Restore selection if valid
            if (currentSelection) {
                this.interfaceSelect.value = currentSelection;
            }

        } catch (error) {
            console.error("Failed to fetch interfaces:", error);
        }
    }

    updateTargetDropdown() {
        if (!this.nodes) return;
        const allNodes = this.nodes.get(); // Returns array of all items
        if (!allNodes) return;

        // Save current selection to restore it if it still exists
        const currentSelection = this.targetSelect.value;

        // Clear existing options except the first one
        this.targetSelect.innerHTML = '<option value="">-- Select Target --</option>';

        // Filter for any node that looks like an AP or has connected clients
        // We'll be more permissive: 'ap', 'AP', or anything with a 'group' of 'ap'
        const targets = allNodes.filter(node => {
            const group = (node.group || '').toLowerCase();
            return group === NodeGroups.AP || group === NodeGroups.ACCESS_POINT;
        });

        // Sort by label or MAC
        targets.sort((a, b) => {
            const labelA = a.label || a.mac || '';
            const labelB = b.label || b.mac || '';
            return labelA.localeCompare(labelB);
        });

        targets.forEach(node => {
            const option = document.createElement('option');
            option.value = node.mac;
            // Show SSID if available, otherwise MAC
            const label = node.ssid ? `${node.ssid} (${node.mac})` : node.mac;
            option.textContent = label;
            this.targetSelect.appendChild(option);
        });

        if (currentSelection) {
            this.targetSelect.value = currentSelection;
        }
    }

    applyMitmPreset() {
        const typeSelect = document.getElementById('deauth-type');
        const countInput = document.getElementById('deauth-count');
        const reasonInput = document.getElementById('deauth-reason');
        const stealthCheck = document.getElementById('deauth-stealth');
        const btn = document.getElementById('mitm-prep-btn');

        if (typeSelect) {
            typeSelect.value = 'targeted';
            this.highlightField(typeSelect);
        }
        if (countInput) {
            countInput.value = '20'; // Short burst to trigger roam
            this.highlightField(countInput);
        }
        if (reasonInput) {
            reasonInput.value = '7';
            this.highlightField(reasonInput);
        }
        if (stealthCheck) {
            stealthCheck.checked = true;
            // Checkbox highlight might be subtle, but okay
        }

        // Button Feedback
        if (btn) {
            const originalText = btn.textContent;
            btn.textContent = "Applied!";
            btn.style.color = "var(--success-color)";
            btn.style.borderColor = "var(--success-color)";
            btn.style.background = "rgba(40, 167, 69, 0.1)"; // Subtle green bg

            setTimeout(() => {
                btn.textContent = originalText;
                btn.style.color = "";
                btn.style.borderColor = "";
                btn.style.background = "";
            }, 1000);
        }

        this.showNotification("MitM Preset Applied", "success");
    }

    highlightField(element) {
        const originalTransition = element.style.transition;
        const originalShadow = element.style.boxShadow;

        element.style.transition = "box-shadow 0.3s, border-color 0.3s";
        element.style.boxShadow = "0 0 8px rgba(255, 179, 0, 0.6)"; // Amber glow
        element.style.borderColor = "rgba(255, 179, 0, 0.8)";

        setTimeout(() => {
            element.style.boxShadow = originalShadow;
            element.style.borderColor = "";
            // Reset transition after effect
            setTimeout(() => {
                element.style.transition = originalTransition;
            }, 300);
        }, 800);
    }

    async startAttack() {
        console.log("[DEBUG] Start Attack Triggered"); // Debug Log
        const targetMAC = this.targetSelect.value;
        const attackType = document.getElementById('deauth-type').value;
        const clientMAC = document.getElementById('deauth-client-mac').value;
        const packetCount = parseInt(document.getElementById('deauth-count').value);
        const packetInterval = parseInt(document.getElementById('deauth-interval').value);
        const reasonCode = parseInt(document.getElementById('deauth-reason').value);
        const legalAck = document.getElementById('deauth-legal-ack').checked;
        const interfaceName = this.interfaceSelect ? this.interfaceSelect.value : "";
        const channelVal = parseInt(document.getElementById('deauth-channel').value);

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
            channel: channelVal || 0, // Use input or 0 for auto-detect
            legal_acknowledgment: legalAck,
            interface: interfaceName
        };

        try {
            const result = await this.apiClient.startDeauthAttack(config);

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

            // Enhanced error handling
            if (error.status === 403) {
                this.showNotification('Insufficient permissions for deauth attacks', 'danger');
            } else if (error.status === 429) {
                this.showNotification('Rate limit exceeded. Please wait before retrying.', 'warning');
            } else if (error.isNetworkError) {
                this.showNotification('Network error. Check your connection.', 'danger');
            } else {
                this.showNotification(`Failed to start attack: ${error.message}`, 'danger');
            }
        }
    }

    async stopAttack(attackId) {
        try {
            await this.apiClient.stopDeauthAttack(attackId);

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
            const data = await this.apiClient.listDeauthAttacks();
            const attacks = data.attacks || [];

            if (attacks.length === 0) {
                this.attackList.innerHTML = DeauthTemplates.emptyList();
                return;
            }

            this.attackList.innerHTML = attacks.map(attack => {
                const duration = attack.end_time
                    ? this.formatDuration(new Date(attack.end_time) - new Date(attack.start_time))
                    : this.formatDuration(Date.now() - new Date(attack.start_time).getTime());
                return DeauthTemplates.renderAttackItem(attack, duration);
            }).join('');

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

    // renderAttackItem moved to templates

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
        // Use Notifications module
        Notifications.show(message, type);

        // Log to Console if available
        if (this.console) {
            this.console.log(message, type);
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
