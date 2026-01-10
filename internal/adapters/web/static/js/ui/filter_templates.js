import { html } from '../core/html.js';

export const FilterTemplates = {
    /**
     * Render a search suggestion item
     * @param {Object|string} item 
     * @returns {string} HTML string
     */
    suggestionItem(item) {
        if (typeof item === 'object') {
            return html`
                <i class="fas ${item.icon} suggestion-icon"></i>
                <span>${item.value}</span>
            `;
        }
        return html`<span>${item}</span>`;
    },

    /**
     * Render a filter tag chip
     * @param {string} type 
     * @param {string} value 
     * @returns {string} HTML string
     */
    filterTag(type, value) {
        return html`
            <span><strong>${type}:</strong> ${value}</span>
            <i class="fas fa-times remove"></i>
        `;
    },

    /**
     * Render a preset button content
     * @param {Object} preset 
     * @returns {string} HTML string
     */
    presetButtonContent(preset) {
        return html`<i class="fas ${preset.icon}"></i> ${preset.name}`;
    }
};
