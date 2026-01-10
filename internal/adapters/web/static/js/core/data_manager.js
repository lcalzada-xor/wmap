/**
 * Data Manager
 * Manages the state of Graph Nodes and Edges using Vis.js DataSet.
 */

import { NodeGroups } from './constants.js';
import { GraphStyler } from '../ui/graph_styler.js';
import { GraphFilter } from './graph_filter.js';
import { EventBus } from './event_bus.js';

// Vis.js Global
const vis = window.vis;

export class DataManager {
    constructor() {
        this.nodes = new vis.DataSet([]);
        this.edges = new vis.DataSet([]);
        // We use a DataView for filtering
        this.nodesView = new vis.DataView(this.nodes, {
            filter: (n) => this.filter(n)
        });

        // Cache for diffing
        this.nodeCache = new Map();
    }

    /**
     * Process incoming graph data (nodes/edges) and update datasets.
     * @param {Object} data - { nodes: [], edges: [] }
     */
    update(data) {
        // Debug logging to trace data flow
        console.log('[DataManager] Received update:', {
            nodes: data.nodes?.length || 0,
            edges: data.edges?.length || 0
        });

        // 1. Process Nodes
        const paramNodes = data.nodes || [];
        const updates = [];

        paramNodes.forEach(n => {
            // Generate signature for diffing
            // We only care about fields that affect styling/logic to avoid excessive redraws
            const signature = `${n.id}|${n.group}|${n.rssi}|${n.channel}|${n.active}|${n.data_tx}|${n.data_rx}|${n.last_seen}|${n.has_handshake}|${n.ssid}|${n.is_randomized}|${n.wps_info}|${n.capabilities}|${n.security}`;

            const cached = this.nodeCache.get(n.id);
            if (!cached || cached.signature !== signature) {
                // Style the node
                const processed = GraphStyler.styleNode(n);
                this.nodeCache.set(n.id, { signature, node: processed });
                updates.push(processed);
            }
        });

        if (updates.length > 0) {
            this.nodes.update(updates);
        }

        // 2. Process Edges
        // Graph data from backend is a complete snapshot, not incremental
        // We need to REPLACE all edges, not merge them
        const paramEdges = data.edges || [];

        // Debug: Log sample edges and breakdown by type
        if (paramEdges.length > 0) {
            console.log('[DataManager] Sample edges (first 5):', paramEdges.slice(0, 5));
            const connectionEdges = paramEdges.filter(e => e.type === 'connection');
            const probeEdges = paramEdges.filter(e => e.type === 'probe');
            console.log('[DataManager] Edge breakdown:', {
                total: paramEdges.length,
                connection: connectionEdges.length,
                probe: probeEdges.length
            });
            if (connectionEdges.length > 0) {
                console.log('[DataManager] Connection edges:', connectionEdges);
            }
        }

        const edgeUpdates = paramEdges.map(e => GraphStyler.styleEdge(e));

        console.log('[DataManager] Styled edges (first 3):', edgeUpdates.slice(0, 3));

        // Full sync: clear old edges and add new ones
        this.edges.clear();
        if (edgeUpdates.length > 0) {
            this.edges.add(edgeUpdates);
            console.log('[DataManager] Added', edgeUpdates.length, 'edges to graph');
            console.log('[DataManager] Current edge count in dataset:', this.edges.length);
        }

        return {
            nodeCount: this.nodes.length,
            edgeCount: this.edges.length,
            updates: updates.length
        };
    }

    clear() {
        this.nodes.clear();
        this.edges.clear();
        this.nodeCache.clear();
    }

    filter(node) {
        return GraphFilter.apply(node);
    }

    refreshView() {
        this.nodesView.refresh();
    }

    getStats() {
        // We need to count based on the *source* dataset or view? 
        // Usually stats reflect the entire known world, not just filtered view.
        const allNodes = this.nodes.get();
        const apCount = allNodes.filter(n => n.group === NodeGroups.AP).length;
        const staCount = allNodes.filter(n => n.group === NodeGroups.STATION).length;
        return { apCount, staCount };
    }
}
