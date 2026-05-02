import { useState, useRef, useCallback } from 'react';
import { useWebSocket } from './useWebSocket';
import { isWSGraphMessage, type GraphData } from '../types/graph';

const GRAPH_THROTTLE_MS = 1000;

/**
 * Hook para manejar los datos del grafo con throttling.
 * Aísla la lógica de estados temporales y control de tiempo.
 */
export function useThrottledGraphData(options: { url: string }) {
  const [graphData, setGraphData] = useState<GraphData | null>(null);
  const lastUpdateRef = useRef<number>(0);
  const pendingDataRef = useRef<GraphData | null>(null);
  const throttleTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const flushPending = useCallback(() => {
    if (pendingDataRef.current) {
      setGraphData(pendingDataRef.current);
      pendingDataRef.current = null;
    }
    lastUpdateRef.current = Date.now();
    throttleTimerRef.current = null;
  }, []);

  const { status } = useWebSocket({
    ...options,
    onMessage: (msg) => {
      if (!isWSGraphMessage(msg)) return;
      const now = Date.now();
      const elapsed = now - lastUpdateRef.current;

      if (elapsed >= GRAPH_THROTTLE_MS) {
        if (throttleTimerRef.current) {
          clearTimeout(throttleTimerRef.current);
          throttleTimerRef.current = null;
        }
        pendingDataRef.current = null;
        lastUpdateRef.current = now;
        setGraphData(msg.payload);
      } else {
        pendingDataRef.current = msg.payload;
        if (!throttleTimerRef.current) {
          throttleTimerRef.current = setTimeout(flushPending, GRAPH_THROTTLE_MS - elapsed);
        }
      }
    }
  });

  return { graphData, status };
}
