import { API } from '../../core/api.js';
import { Notifications } from '../notifications.js';

export class ChannelModal {
    static init() {
        this.interfaceCapabilities = {};
        this.channelContainers = {
            '2.4': document.getElementById('channels-24ghz'),
            '5-1': document.getElementById('channels-5ghz-unii1'),
            '5-2': document.getElementById('channels-5ghz-unii2'),
            '5-2e': document.getElementById('channels-5ghz-unii2ext'),
            '5-3': document.getElementById('channels-5ghz-unii3')
        };
        this._saveTimeout = null;

        const modal = document.getElementById('channel-modal');
        const btnClose = document.getElementById('btn-channel-modal-close');
        const btnOpen = document.getElementById('btn-channel-config');

        if (!modal || !btnOpen) {
            console.error("ChannelModal: Missing critical elements", { modal, btnOpen });
            return;
        }



        // Inject Interface Selector if missing
        const modalContent = modal.querySelector('.modal-content');
        const header = modal.querySelector('h3');

        let interfaceContainer = document.getElementById('channel-interface-container');
        if (!interfaceContainer) {
            interfaceContainer = document.createElement('div');
            interfaceContainer.id = 'channel-interface-container';
            interfaceContainer.style.marginBottom = '20px';
            interfaceContainer.style.background = 'rgba(255,255,255,0.05)';
            interfaceContainer.style.padding = '10px';
            interfaceContainer.style.borderRadius = '8px';
            interfaceContainer.innerHTML = `
                <label style="display:block; font-size:0.8em; color:var(--text-secondary); margin-bottom:5px;">Target Interface</label>
                <select id="channel-interface-select" style="width:100%; padding:8px; background:rgba(0,0,0,0.3); color:white; border:1px solid var(--panel-border); border-radius:4px;">
                    <option value="">Loading interfaces...</option>
                </select>
            `;
            // Insert after H3
            if (header && header.nextSibling) {
                modalContent.insertBefore(interfaceContainer, header.nextSibling);
            } else {
                modalContent.appendChild(interfaceContainer);
            }
        }

        const ifaceSelect = document.getElementById('channel-interface-select');
        ifaceSelect.onchange = () => {
            this.loadChannels();
        };

        btnOpen.onclick = () => {
            modal.classList.add('active'); // CSS Transition
            // Load interfaces then channels
            API.getInterfaces().then(data => {
                const interfaces = data.interfaces || [];
                // Store capabilities map: name -> capabilities
                this.interfaceCapabilities = {};

                ifaceSelect.innerHTML = '';
                interfaces.forEach(info => {
                    const ifaceName = info.name || info; // Handle object or string
                    const caps = info.capabilities || {};
                    this.interfaceCapabilities[ifaceName] = caps;

                    const opt = document.createElement('option');
                    opt.value = ifaceName;

                    // Display interface name with supported bands
                    const bands = caps.supported_bands || [];
                    const bandStr = bands.length > 0 ? ` (${bands.join(', ')})` : '';
                    opt.innerText = `${ifaceName}${bandStr}`;

                    // Color code 5GHz-capable interfaces
                    if (bands.includes('5GHz')) {
                        opt.style.color = '#4CAF50'; // Green for 5GHz support
                        opt.style.fontWeight = '500';
                    }

                    ifaceSelect.appendChild(opt);
                });

                // Select first by default if available
                if (interfaces.length > 0) {
                    // Trigger load for first/selected interface
                    this.loadChannels();
                }
            }).catch(err => {
                console.error("Failed to load interfaces", err);
                Notifications.show("Failed to load interfaces", "danger");
            });
        };

        btnClose.onclick = () => modal.classList.remove('active');

        document.getElementById('btn-select-all-channels').onclick = () => this.toggleAllChannels(true);
        document.getElementById('btn-select-none-channels').onclick = () => this.toggleAllChannels(false);
    }

    static loadChannels() {
        const ifaceSelect = document.getElementById('channel-interface-select');
        const iface = ifaceSelect ? ifaceSelect.value : null;

        // Get capabilities for this interface
        const caps = this.interfaceCapabilities && iface ? this.interfaceCapabilities[iface] : null;
        const supportedSet = caps ? new Set(caps.supported_channels || []) : null;

        API.getChannels(iface).then(data => {
            const currentChannels = new Set(data.channels); // active channels

            // Define bands
            const bands = [
                { id: '2.4', channels: Array.from({ length: 13 }, (_, i) => i + 1) },
                { id: '5-1', channels: [36, 40, 44, 48] },
                { id: '5-2', channels: [52, 56, 60, 64] },
                { id: '5-2e', channels: [100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140] },
                { id: '5-3', channels: [149, 153, 157, 161, 165] }
            ];

            bands.forEach(band => {
                const container = this.channelContainers[band.id];
                if (!container) return;
                container.innerHTML = ''; // Clear

                band.channels.forEach(ch => {
                    const el = document.createElement('div');
                    const isSupported = !supportedSet || supportedSet.has(ch);
                    const isActive = currentChannels.has(ch);

                    el.className = `channel-toggle ${isActive ? 'active' : ''} ${!isSupported ? 'disabled' : ''}`;

                    // Show channel number with interface badge if active
                    if (isActive && iface) {
                        el.innerHTML = `
                            ${ch}
                            <span class="iface-badge">${iface}</span>
                        `;
                    } else {
                        el.innerText = ch;
                    }

                    el.dataset.channel = ch;

                    if (!isSupported) {
                        el.style.opacity = '0.3';
                        el.style.cursor = 'not-allowed';
                        el.title = `Not supported by ${iface || 'hardware'}`;
                    } else {
                        el.onclick = () => {
                            el.classList.toggle('active');
                            this.saveChannels(); // Auto-save for iOS feel
                        };
                    }

                    container.appendChild(el);
                });
            });
        });
    }

    static toggleAllChannels(state) {
        document.querySelectorAll('.channel-toggle').forEach(el => {
            // Check if disabled first
            if (el.classList.contains('disabled')) return;

            if (state) el.classList.add('active');
            else el.classList.remove('active');
        });
        this.saveChannels();
    }

    static saveChannels() {
        const ifaceSelect = document.getElementById('channel-interface-select');
        const iface = ifaceSelect ? ifaceSelect.value : null;

        const channels = [];
        document.querySelectorAll('.channel-toggle.active').forEach(el => {
            channels.push(parseInt(el.dataset.channel));
        });

        // Debounce simple
        if (this._saveTimeout) clearTimeout(this._saveTimeout);
        this._saveTimeout = setTimeout(() => {
            API.updateChannels(channels, iface).then(() => {
                Notifications.show("Channels Updated for " + (iface || "Global"), "success");
            });
        }, 500);
    }
}
