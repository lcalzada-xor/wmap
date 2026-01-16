/**
 * Saturation Manager
 * Protects the frontend from freezing during high-density attacks (e.g., Auth Flood).
 * Dynamically filters out low-priority nodes when the total count exceeds a safety threshold.
 */

import { NodeGroups } from './constants.js';
import { Notifications } from '../ui/notifications.js';

export const SaturationManager = {
    // Configuration
    MAX_NODES: 500,           // Hard limit for visible nodes
    SATURATION_THRESHOLD: 400, // Warning/Activation threshold

    // State
    isSaturated: false,
    allowedNodeIds: new Set(),

    /**
     * Initialize the manager
     */
    init() {
        console.log("[SaturationManager] Initialized");
        this.reset();
    },

    reset() {
        this.isSaturated = false;
        this.allowedNodeIds.clear();
    },

    /**
     * Update the allowed list based on current node set
     * @param {Array} nodes - List of all current nodes from the backend
     */
    update(nodes) {
        const totalNodes = nodes.length;

        // Check if we need to activate saturation mode
        if (totalNodes > this.SATURATION_THRESHOLD) {
            if (!this.isSaturated) {
                this.isSaturated = true;
                Notifications.show(`High Traffic Detected (${totalNodes} nodes). Optimizing display...`, 'warning');
            }
        } else {
            if (this.isSaturated) {
                this.isSaturated = false;
                Notifications.show("Traffic normalized. Display optimization disabled.", 'success');
            }
            // If not saturated, we don't need to filter, but we clear the set to save memory/logic
            this.allowedNodeIds.clear();
            return;
        }

        // If saturated, calculate scores and filter
        this.calculatePriority(nodes);
    },

    /**
     * Calculate node priority and populate allowedNodeIds
     * Scoring Rules:
     * - APs: Always show (Score 100)
     * - Connected Stations (Associated): High Priority (Score 80)
     * - Stations with Handshakes: High Priority (Score 90)
     * - Stations with high data traffic: Medium Priority (Score 50 + traffic bonus)
     * - Idle/New Stations: Low Priority (Score 0-10)
     */
    calculatePriority(nodes) {
        // 1. Calculate scores
        const scoredNodes = nodes.map(node => {
            let score = 0;

            // Rule 1: Always show Infrastructure
            if (node.group === NodeGroups.AP || node.group === NodeGroups.NETWORK) {
                score = 1000;
            }
            // Rule 2: Handshakes are critical
            else if (node.has_handshake) {
                score = 900;
            }
            // Rule 3: High traffic stations are likely real
            else {
                const traffic = (node.data_tx || 0) + (node.data_rx || 0);
                if (traffic > 1000) score += 50;
                if (traffic > 10000) score += 50;

                // Recent activity bonus
                if (node.last_seen) {
                    const secondsAgo = (Date.now() - new Date(node.last_seen).getTime()) / 1000;
                    if (secondsAgo < 10) score += 20;
                }
            }

            return { id: node.id, score };
        });

        // 2. Sort by score descending
        scoredNodes.sort((a, b) => b.score - a.score);

        // 3. Keep top N nodes
        this.allowedNodeIds.clear();
        const limit = Math.min(scoredNodes.length, this.MAX_NODES);

        for (let i = 0; i < limit; i++) {
            this.allowedNodeIds.add(scoredNodes[i].id);
        }
    },

    /**
     * Check if a node should be visible
     * @param {string} nodeId 
     * @returns {boolean}
     */
    shouldShow(nodeId) {
        if (!this.isSaturated) return true;
        return this.allowedNodeIds.has(nodeId);
    }
};
