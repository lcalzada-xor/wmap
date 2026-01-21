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
        this.presetSelect = document.getElementById('deauth-preset');
        this.advancedToggle = document.getElementById('btn-toggle-advanced-deauth');
        this.advancedOptions = document.getElementById('deauth-advanced-options');
        this.spoofCheck = document.getElementById('deauth-spoof');
        this.jitterCheck = document.getElementById('deauth-jitter');
        this.reasonFuzzCheck = document.getElementById('deauth-reason-fuzz');
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

        // Toggle Advanced Options
        this.advancedToggle?.addEventListener('click', () => {
            this.toggleAdvancedOptions();
        });

        // Presets
        this.presetSelect?.addEventListener('change', () => {
            this.applyPreset();
        });

        // Start periodic updates
        this.startPeriodicUpdates();

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

        // Check if current selection is in the filtered list
        const inList = targets.some(n => n.mac === currentSelection);

        // If current selection is valid but filtered out (e.g. not identified as AP yet), add it back
        let preservedOption = null;
        if (currentSelection && !inList && this.nodes) {
            const missedNode = this.nodes.get(currentSelection);
            if (missedNode) {
                preservedOption = {
                    mac: missedNode.mac,
                    ssid: missedNode.ssid,
                    label: missedNode.label
                };
                // Add to start of list
                targets.unshift(preservedOption);
            } else {
                // If not in nodes anymore, we can't really do much unless we want to keep a stale value
                // But manual append logic in openPanel creates an option. 
                // If that node is not in this.nodes at all, we lose it.
                // We should assume if value is set, we want to keep it.
                const option = document.createElement('option');
                option.value = currentSelection;
                option.textContent = currentSelection + " (Preserved)";
                this.targetSelect.appendChild(option);
            }
        }

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

    toggleAdvancedOptions() {
        if (!this.advancedOptions || !this.advancedToggle) return;

        const icon = this.advancedToggle.querySelector('i');
        const isHidden = this.advancedOptions.style.display === 'none';

        this.advancedOptions.style.display = isHidden ? 'block' : 'none';

        if (icon) {
            icon.style.transform = isHidden ? 'rotate(90deg)' : 'rotate(0deg)';
        }
    }

    applyPreset() {
        const preset = this.presetSelect.value;
        const typeSelect = document.getElementById('deauth-type');
        const countInput = document.getElementById('deauth-count');
        const intervalInput = document.getElementById('deauth-interval');
        const reasonInput = document.getElementById('deauth-reason');

        if (preset === 'custom') return;

        // Default Reset function
        const setVal = (el, val) => {
            if (el) {
                el.value = val;
                this.highlightField(el);
            }
        };

        const setStealth = (spoof, jitter, fuzz) => {
            if (this.spoofCheck) this.spoofCheck.checked = spoof;
            if (this.jitterCheck) this.jitterCheck.checked = jitter;
            if (this.reasonFuzzCheck) this.reasonFuzzCheck.checked = fuzz;
        };

        switch (preset) {
            case 'handshake':
                setVal(typeSelect, 'targeted');
                setVal(countInput, '25');
                setVal(intervalInput, '100');
                setVal(reasonInput, '7');
                setStealth(true, true, true);
                break;
            case 'disconnect':
                setVal(typeSelect, 'broadcast');
                setVal(countInput, '0'); // Continuous
                setVal(intervalInput, '10'); // Fast flood
                setVal(reasonInput, '2'); // Previous auth invalid
                setStealth(false, false, false); // Max power
                break;
            case 'stealth':
                setVal(countInput, '0');
                setVal(intervalInput, '500'); // Slow
                setStealth(true, true, true);
                break;
            case 'annoy':
                setVal(typeSelect, 'broadcast');
                setVal(countInput, '5');
                setVal(intervalInput, '2000'); // Every 2s
                setVal(reasonInput, '1');
                setStealth(true, true, true);
                break;
        }

        this.showNotification(`Applied preset: ${preset}`, "success");
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
            interface: interfaceName,
            // Stealth & Optimizations
            spoof_source: this.spoofCheck ? this.spoofCheck.checked : false,
            use_jitter: this.jitterCheck ? this.jitterCheck.checked : false,
            use_reason_fuzzing: this.reasonFuzzCheck ? this.reasonFuzzCheck.checked : false
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

    async stopAttack(attackId, force = false) {
        try {
            await this.apiClient.stopDeauthAttack(attackId, force);

            this.showNotification(`Attack attached (Force: ${force}) stopped`, 'success');
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
                    const attackId = e.target.dataset.attackId || e.target.closest('.btn-stop-attack').dataset.attackId;
                    this.stopAttack(attackId);
                });
            });

            // Add event listeners to force stop buttons
            this.attackList.querySelectorAll('.btn-force-stop-attack').forEach(btn => {
                btn.addEventListener('click', (e) => {
                    const attackId = e.target.dataset.attackId || e.target.closest('.btn-force-stop-attack').dataset.attackId;
                    if (confirm("Are you sure you want to FORCE stop this attack? This might leave the interface in an unstable state.")) {
                        this.stopAttack(attackId, true);
                    }
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
