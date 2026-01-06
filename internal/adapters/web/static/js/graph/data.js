/**
 * Graph Data Manager
 * Handles DataSet manipulation and Styling logic.
 */

import { State } from '../core/state.js';
import { GraphStyler } from '../ui/graph_styler.js';
import { GraphFilter } from '../core/graph_filter.js';

export const DataManager = {
    processNodes(rawNodes) {
        return rawNodes.map(n => GraphStyler.styleNode(n));
    },

    processEdges(rawEdges, nodesDataSet) {
        return rawEdges.map(e => GraphStyler.styleEdge(e));
    },

    // Old styleNode and styleEdge removed

    // Filter Function used by DataView
    // Filter Function used by DataView
    filter(node) {
        return GraphFilter.apply(node);
    }
};
