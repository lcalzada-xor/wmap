/**
 * Executive Report Modal Controller
 * Handles report generation with date range, format selection, and organization name
 */

import { API } from '../core/api.js';
import { Notifications } from './notifications.js';

export class ReportModal {
    constructor() {
        this.modal = document.getElementById('executive-report-modal');
        this.startDateInput = document.getElementById('report-start-date');
        this.endDateInput = document.getElementById('report-end-date');
        this.orgNameInput = document.getElementById('report-org-name');
        this.generateBtn = document.getElementById('btn-report-generate');
        this.cancelBtn = document.getElementById('btn-report-cancel');
        this.loadingOverlay = document.getElementById('report-loading');

        this.selectedFormat = 'pdf';
        this.init();
    }

    init() {
        // Set default dates (last 30 days)
        this.setDefaultDates();

        // Date preset pills
        const presetPills = document.querySelectorAll('.preset-pill');
        presetPills.forEach(pill => {
            pill.addEventListener('click', () => {
                presetPills.forEach(p => p.classList.remove('active'));
                pill.classList.add('active');

                const days = pill.dataset.days;
                if (days === 'custom') {
                    // Keep current dates
                } else {
                    this.setPresetDates(parseInt(days));
                }
            });
        });

        // Format selection
        const formatOptions = document.querySelectorAll('.format-option');
        formatOptions.forEach(option => {
            option.addEventListener('click', () => {
                formatOptions.forEach(o => o.classList.remove('active'));
                option.classList.add('active');
                this.selectedFormat = option.dataset.format;
            });
        });

        // Buttons
        this.generateBtn.addEventListener('click', () => this.generateReport());
        this.cancelBtn.addEventListener('click', () => this.close());

        // Close on backdrop click
        this.modal.addEventListener('click', (e) => {
            if (e.target === this.modal) {
                this.close();
            }
        });

        // ESC key to close
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape' && this.modal.classList.contains('active')) {
                this.close();
            }
        });
    }

    setDefaultDates() {
        const today = new Date();
        const thirtyDaysAgo = new Date();
        thirtyDaysAgo.setDate(today.getDate() - 30);

        this.endDateInput.value = this.formatDate(today);
        this.startDateInput.value = this.formatDate(thirtyDaysAgo);
    }

    setPresetDates(days) {
        const today = new Date();
        const startDate = new Date();
        startDate.setDate(today.getDate() - days);

        this.endDateInput.value = this.formatDate(today);
        this.startDateInput.value = this.formatDate(startDate);
    }

    formatDate(date) {
        const year = date.getFullYear();
        const month = String(date.getMonth() + 1).padStart(2, '0');
        const day = String(date.getDate()).padStart(2, '0');
        return `${year}-${month}-${day}`;
    }

    open() {
        this.setDefaultDates();
        this.modal.classList.add('active');

        // Focus organization name input
        setTimeout(() => {
            this.orgNameInput.focus();
            this.orgNameInput.select();
        }, 300);
    }

    close() {
        this.modal.classList.remove('active');
    }

    showLoading() {
        this.loadingOverlay.style.display = 'flex';
        this.generateBtn.disabled = true;
    }

    hideLoading() {
        this.loadingOverlay.style.display = 'none';
        this.generateBtn.disabled = false;
    }

    async generateReport() {
        const startDate = this.startDateInput.value;
        const endDate = this.endDateInput.value;
        const orgName = this.orgNameInput.value.trim();

        // Validation
        if (!startDate || !endDate) {
            Notifications.show('Please select a date range', 'warning');
            return;
        }

        if (new Date(startDate) > new Date(endDate)) {
            Notifications.show('Start date must be before end date', 'warning');
            return;
        }

        if (!orgName) {
            Notifications.show('Please enter an organization name', 'warning');
            return;
        }

        this.showLoading();

        try {
            const response = await fetch('/api/reports/executive', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    start_date: startDate,
                    end_date: endDate,
                    org_name: orgName,
                    format: this.selectedFormat
                })
            });

            if (!response.ok) {
                const errorText = await response.text();
                throw new Error(errorText || 'Report generation failed');
            }

            if (this.selectedFormat === 'pdf') {
                // Download PDF
                const blob = await response.blob();
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = `wmap-executive-summary-${orgName.replace(/\s+/g, '-').toLowerCase()}.pdf`;
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                window.URL.revokeObjectURL(url);

                Notifications.show('Executive Summary PDF downloaded successfully', 'success');
            } else {
                // Download JSON
                const data = await response.json();
                const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = `wmap-executive-summary-${orgName.replace(/\s+/g, '-').toLowerCase()}.json`;
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                window.URL.revokeObjectURL(url);

                Notifications.show('Executive Summary JSON downloaded successfully', 'success');
            }

            this.close();
        } catch (error) {
            console.error('Report generation error:', error);
            Notifications.show(`Failed to generate report: ${error.message}`, 'danger');
        } finally {
            this.hideLoading();
        }
    }
}
