import { useCallback, useRef, useState } from 'react';

interface Position { x: number; y: number }

export function useDraggable(initialPos?: Position) {
  const [pos, setPos] = useState<Position>(initialPos ?? { x: 0, y: 0 });
  const posRef = useRef(pos);
  posRef.current = pos;

  const onMouseDown = useCallback((e: React.MouseEvent) => {
    if (e.button !== 0) return;
    e.preventDefault();
    const origin = { x: e.clientX, y: e.clientY };
    const start = { ...posRef.current };

    const onMove = (ev: MouseEvent) => {
      setPos({
        x: start.x + ev.clientX - origin.x,
        y: start.y + ev.clientY - origin.y,
      });
    };

    const onUp = () => {
      window.removeEventListener('mousemove', onMove);
      window.removeEventListener('mouseup', onUp);
    };

    window.addEventListener('mousemove', onMove);
    window.addEventListener('mouseup', onUp);
  }, []);

  return { pos, onMouseDown };
}
