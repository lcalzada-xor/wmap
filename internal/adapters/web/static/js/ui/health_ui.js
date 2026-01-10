/**
 * HealthUI - Interface Health Monitor Popup
 * Displays real-time metrics for network interfaces
 */
import { API } from '../core/api.js';

class HealthUI {
    constructor() {
        this.popup = null;
        this.isOpen = false;
        this.pollInterval = null;
        this.init();
    }

    init() {
        this.createPopup();
        this.attachEventListeners();
    }

    createPopup() {
        const popup = document.createElement('div');
        popup.className = 'health-popup hidden';
        popup.innerHTML = `
            <div class="health-popup-header">
                <h3>Interface Health Monitor</h3>
                <button class="health-close-btn" aria-label="Close">&times;</button>
            </div>
            <div class="health-popup-body">
                <div class="health-loading">Loading metrics...</div>
            </div>
        `;
        document.body.appendChild(popup);
        this.popup = popup;
    }

    attachEventListeners() {
        const closeBtn = this.popup.querySelector('.health-close-btn');
        closeBtn.addEventListener('click', () => this.close());

        // Close on Escape key
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape' && this.isOpen) {
                this.close();
            }
        });
    }

    async open() {
        this.isOpen = true;
        this.popup.classList.remove('hidden');
        await this.fetchAndRender();

        // Poll every 2 seconds while open
        this.pollInterval = setInterval(() => this.fetchAndRender(), 2000);
    }

    close() {
        this.isOpen = false;
        this.popup.classList.add('hidden');
        if (this.pollInterval) {
            clearInterval(this.pollInterval);
            this.pollInterval = null;
        }
    }

    async fetchAndRender() {
        try {
            const data = await API.getInterfaces();
            this.render(data.interfaces || []);
        } catch (error) {
            console.error('Health UI fetch error:', error);

            // Enhanced error handling
            if (error.status === 401) {
                // Redirect handled by API wrapper
                return;
            }

            const errorMessage = error.isNetworkError
                ? 'Network error. Check your connection.'
                : (error.status === 403
                    ? 'Insufficient permissions to view interface health'
                    : error.message || 'Failed to fetch interface data');

            this.renderError(errorMessage);
        }
    }

    render(interfaces) {
        const body = this.popup.querySelector('.health-popup-body');

        if (interfaces.length === 0) {
            body.innerHTML = '<div class="health-empty">No interfaces found</div>';
            return;
        }

        body.innerHTML = interfaces.map(iface => `
            <div class="health-interface-card">
                <div class="health-interface-header">
                    <span class="health-interface-name">${iface.name}</span>
                    <span class="health-interface-mac">${iface.mac}</span>
                </div>
                <div class="health-metrics-grid">
                    <div class="health-metric">
                        <span class="health-metric-label">Packets Received</span>
                        <span class="health-metric-value">${this.formatNumber(iface.metrics?.packets_received || 0)}</span>
                    </div>
                    <div class="health-metric">
                        <span class="health-metric-label">Packets Dropped</span>
                        <span class="health-metric-value ${iface.metrics?.packets_dropped > 0 ? 'health-warning' : ''}">${this.formatNumber(iface.metrics?.packets_dropped || 0)}</span>
                    </div>
                    <div class="health-metric">
                        <span class="health-metric-label">App Queue Drops</span>
                        <span class="health-metric-value ${iface.metrics?.app_packets_dropped > 0 ? 'health-critical' : ''}">${this.formatNumber(iface.metrics?.app_packets_dropped || 0)}</span>
                    </div>
                    <div class="health-metric">
                        <span class="health-metric-label">Interface Drops</span>
                        <span class="health-metric-value ${iface.metrics?.packets_if_dropped > 0 ? 'health-warning' : ''}">${this.formatNumber(iface.metrics?.packets_if_dropped || 0)}</span>
                    </div>
                    <div class="health-metric">
                        <span class="health-metric-label">Queue Health</span>
                        <div class="health-queue-container">
                            <div class="health-queue-bar">
                                <div class="health-queue-fill ${this.getQueueHealthClass(iface.metrics)}" style="width: ${this.getQueueHealthPercentage(iface.metrics)}%"></div>
                            </div>
                            <span class="health-metric-value ${this.getQueueHealthClass(iface.metrics)}">${this.formatQueueHealth(iface.metrics)}</span>
                        </div>
                    </div>
                    <div class="health-metric">
                        <span class="health-metric-label">Current Channels</span>
                        <span class="health-metric-value">${this.formatChannels(iface.current_channels)}</span>
                    </div>
                    <div class="health-metric">
                        <span class="health-metric-label">Error Count</span>
                        <span class="health-metric-value ${iface.metrics?.error_count > 0 ? 'health-critical' : ''}">${this.formatNumber(iface.metrics?.error_count || 0)}</span>
                    </div>
                    <div class="health-metric">
                        <span class="health-metric-label">Total Drop Rate</span>
                        <span class="health-metric-value ${this.getDropRateClass(iface.metrics)}">${this.formatDropRate(iface.metrics)}</span>
                    </div>
                </div>
            </div>
        `).join('');
    }

    getQueueHealthClass(metrics) {
        if (!metrics) return '';
        const dropRate = this.calculateDropRate(metrics);
        if (dropRate > 5) return 'health-critical';
        if (dropRate > 1) return 'health-warning';
        return 'health-good';
    }

    formatQueueHealth(metrics) {
        if (!metrics || !metrics.packets_received) return 'N/A';
        const dropRate = this.calculateDropRate(metrics);
        const health = Math.max(0, 100 - dropRate).toFixed(1);
        return `${health}%`;
    }

    calculateDropRate(metrics) {
        const total = (metrics.packets_received || 0) + (metrics.app_packets_dropped || 0);
        if (total === 0) return 0;
        return ((metrics.app_packets_dropped || 0) / total) * 100;
    }

    getQueueHealthPercentage(metrics) {
        if (!metrics || !metrics.packets_received) return 0;
        const dropRate = this.calculateDropRate(metrics);
        return Math.max(0, 100 - dropRate);
    }

    formatDropRate(metrics) {
        if (!metrics || !metrics.packets_received) return '0.0%';
        const totalDrops = (metrics.packets_dropped || 0) +
            (metrics.app_packets_dropped || 0) +
            (metrics.packets_if_dropped || 0);
        const total = (metrics.packets_received || 0) + totalDrops;
        if (total === 0) return '0.0%';
        const rate = (totalDrops / total) * 100;
        return rate.toFixed(2) + '%';
    }

    getDropRateClass(metrics) {
        if (!metrics || !metrics.packets_received) return '';
        const totalDrops = (metrics.packets_dropped || 0) +
            (metrics.app_packets_dropped || 0) +
            (metrics.packets_if_dropped || 0);
        const total = (metrics.packets_received || 0) + totalDrops;
        if (total === 0) return '';
        const rate = (totalDrops / total) * 100;
        if (rate > 5) return 'health-critical';
        if (rate > 1) return 'health-warning';
        return 'health-good';
    }

    renderError(message) {
        const body = this.popup.querySelector('.health-popup-body');
        body.innerHTML = `<div class="health-error">Error: ${message}</div>`;
    }

    formatNumber(num) {
        return num.toLocaleString();
    }

    formatChannels(channels) {
        if (!channels || channels.length === 0) return 'None';
        if (channels.length > 5) return `${channels.length} channels`;
        return channels.join(', ');
    }
}

export default HealthUI;
