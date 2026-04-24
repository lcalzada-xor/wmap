import { useEffect, useState, useCallback, useRef } from 'react';

export const WSStatus = {
  CONNECTING: 'CONNECTING',
  OPEN: 'OPEN',
  CLOSED: 'CLOSED',
  ERROR: 'ERROR'
} as const;

export type WSStatus = typeof WSStatus[keyof typeof WSStatus];

interface UseWebSocketOptions {
  url: string;
  reconnect?: boolean;
  reconnectInterval?: number;
}

export function useWebSocket({ 
  url, 
  reconnect = true, 
  reconnectInterval = 3000 
}: UseWebSocketOptions) {
  const [status, setStatus] = useState<WSStatus>(WSStatus.CLOSED);
  const [lastMessage, setLastMessage] = useState<any>(null);
  
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimerRef = useRef<number | null>(null);

  const connect = useCallback(() => {
    if (wsRef.current?.readyState === WebSocket.OPEN) return;

    setStatus(WSStatus.CONNECTING);
    try {
      const ws = new WebSocket(url);

      ws.onopen = () => {
        setStatus(WSStatus.OPEN);
        console.log(`[WebSocket] Connected to ${url}`);
      };

      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          setLastMessage(data);
        } catch (e) {
          setLastMessage(event.data);
        }
      };

      ws.onclose = () => {
        setStatus(WSStatus.CLOSED);
        console.log(`[WebSocket] Disconnected from ${url}`);
        
        if (reconnect) {
          reconnectTimerRef.current = window.setTimeout(() => {
            connect();
          }, reconnectInterval);
        }
      };

      ws.onerror = (err) => {
        setStatus(WSStatus.ERROR);
        console.error(`[WebSocket] Error:`, err);
        // onclose is typically called after onerror
      };

      wsRef.current = ws;
    } catch (error) {
      console.error('[WebSocket] Initialization error:', error);
      setStatus(WSStatus.ERROR);
    }
  }, [url, reconnect, reconnectInterval]);

  const sendMessage = useCallback((msg: any) => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(typeof msg === 'string' ? msg : JSON.stringify(msg));
    } else {
      console.warn('[WebSocket] Cannot send message, connection not open');
    }
  }, []);

  useEffect(() => {
    connect();

    return () => {
      if (reconnectTimerRef.current) {
        clearTimeout(reconnectTimerRef.current);
      }
      if (wsRef.current) {
        wsRef.current.close();
      }
    };
  }, [connect]);

  return { status, lastMessage, sendMessage };
}
