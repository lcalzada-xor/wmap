/**
 * Graph Data Manager
 * Handles DataSet manipulation and Styling logic.
 */


import { GraphStyler } from '../ui/graph_styler.js';
import { GraphFilter } from '../core/graph_filter.js';
import { SaturationManager } from '../core/saturation_manager.js';

export const DataManager = {
    // Cache for differential updates
    // Map<string, {}> stores the last known state of processed nodes by ID
    nodeCache: new Map(),

    processNodes(rawNodes) {
        // Update saturation state based on total volume
        SaturationManager.update(rawNodes);

        const updates = [];

        rawNodes.forEach(n => {
            // Create a simple signature to check for changes
            // We only care about fields that affect styling or data display
            const signature = `${n.id}|${n.group}|${n.rssi}|${n.channel}|${n.active}|${n.data_tx}|${n.data_rx}|${n.last_seen}|${n.has_handshake}|${n.ssid}|${n.is_randomized}|${n.wps_info}|${n.capabilities}|${n.security}`;

            const cached = this.nodeCache.get(n.id);
            if (!cached || cached.signature !== signature) {
                // Node has changed or is new
                const processed = GraphStyler.styleNode(n);
                this.nodeCache.set(n.id, { signature, node: processed });
                updates.push(processed);
            }
        });

        return updates;
    },

    processEdges(rawEdges, nodesDataSet) {
        // Edges are fewer and usually static, but we can optimize similarly if needed.
        // For now, simple mapping is okay, but let's check basic validity.
        return rawEdges.map(e => GraphStyler.styleEdge(e));
    },

    // Old styleNode and styleEdge removed

    // Filter Function used by DataView
    // Filter Function used by DataView
    filter(node) {
        return GraphFilter.apply(node);
    }
};
