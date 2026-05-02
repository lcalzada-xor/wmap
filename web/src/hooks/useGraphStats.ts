import { useMemo } from 'react';
import type { GraphData } from '../types/graph';

/**
 * Hook para calcular estadísticas de los nodos.
 */
export function useGraphStats(graphData: GraphData | null) {
  return useMemo(() => {
    if (!graphData) return { apCount: 0, stationCount: 0, networkCount: 0, edgeCount: 0, totalNodes: 0 };

    let apCount = 0, stationCount = 0, networkCount = 0;
    graphData.nodes.forEach(n => {
      if (n.group === 'ap') apCount++;
      else if (n.group === 'station') stationCount++;
      else if (n.group === 'network') networkCount++;
    });

    return { 
      apCount, 
      stationCount, 
      networkCount, 
      edgeCount: graphData.edges.length,
      totalNodes: graphData.nodes.length 
    };
  }, [graphData]);
}
