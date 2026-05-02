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
  onMessage?: (data: unknown) => void;
  saveLastMessage?: boolean;
}

export function useWebSocket({ 
  url, 
  reconnect = true, 
  reconnectInterval = 3000,
  onMessage,
  saveLastMessage = true
}: UseWebSocketOptions) {
  const [status, setStatus] = useState<WSStatus>(WSStatus.CLOSED);
  const [lastMessage, setLastMessage] = useState<unknown>(null);
  
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const retryCountRef = useRef(0);

  // Keep a stable ref to the latest options so the connect function
  // (called from the reconnect timer) always sees fresh values without
  // needing to be recreated on every render — which would trigger the
  // useEffect and open a new connection in React StrictMode.
  const optionsRef = useRef({ url, reconnect, reconnectInterval, onMessage, saveLastMessage });
  useEffect(() => {
    optionsRef.current = { url, reconnect, reconnectInterval, onMessage, saveLastMessage };
  }, [url, reconnect, reconnectInterval, onMessage, saveLastMessage]);

  const connect = useCallback(function doConnect() {
    if (wsRef.current?.readyState === WebSocket.OPEN) return;

    const { url: wsUrl, reconnect: shouldReconnect, reconnectInterval: interval } = optionsRef.current;

    setStatus(WSStatus.CONNECTING);
    try {
      const ws = new WebSocket(wsUrl);

      ws.onopen = () => {
        setStatus(WSStatus.OPEN);
        retryCountRef.current = 0;
        console.log(`[WebSocket] Connected to ${wsUrl}`);
      };

      ws.onmessage = (event) => {
        if (typeof event.data !== 'string') {
          console.warn('[WebSocket] Received non-string payload. Ignoring.');
          return;
        }

        try {
          const data: unknown = JSON.parse(event.data);
          if (optionsRef.current.saveLastMessage) {
            setLastMessage(data);
          }
          if (optionsRef.current.onMessage) {
            optionsRef.current.onMessage(data);
          }
        } catch {
          if (optionsRef.current.saveLastMessage) {
            setLastMessage(event.data);
          }
          if (optionsRef.current.onMessage) {
            optionsRef.current.onMessage(event.data);
          }
        }
      };

      ws.onclose = () => {
        setStatus(WSStatus.CLOSED);
        console.log(`[WebSocket] Disconnected from ${wsUrl}`);
        
        if (shouldReconnect) {
          const backoffTime = Math.min(interval * (2 ** retryCountRef.current), 30000);
          retryCountRef.current += 1;
          
          reconnectTimerRef.current = setTimeout(() => {
            doConnect();
          }, backoffTime);
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
  // connect is stable — it reads all options from optionsRef
  }, []);

  const sendMessage = useCallback((msg: unknown) => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(typeof msg === 'string' ? msg : JSON.stringify(msg));
    } else {
      console.warn('[WebSocket] Cannot send message, connection not open');
    }
  }, []);

  // Empty dependency array: connect once on mount. StrictMode will unmount/remount
  // this effect in development, but since we clean up the socket on unmount the
  // second mount will correctly open a fresh connection.
  useEffect(() => {
    connect();

    return () => {
      if (reconnectTimerRef.current) {
        clearTimeout(reconnectTimerRef.current);
      }
      if (wsRef.current) {
        // Prevent onclose from triggering a reconnect when unmounting
        wsRef.current.onclose = null;
        wsRef.current.close();
      }
    };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return { status, lastMessage, sendMessage };
}
