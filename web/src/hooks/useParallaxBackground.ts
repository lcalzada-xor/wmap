import { useRef, useEffect } from 'react';

/**
 * Hook para manejar el efecto Parallax del fondo.
 * Aísla completamente la manipulación directa del DOM y el RAF.
 */
export function useParallaxBackground() {
  const graphLayerRef = useRef<HTMLDivElement>(null);
  const bgRafRef = useRef<number | null>(null);

  useEffect(() => {
    const target = { x: 0.5, y: 0.5 };
    const current = { x: 0.5, y: 0.5 };
    const LERP = 0.04;

    const handleMouseMove = (e: MouseEvent) => {
      target.x = e.clientX / window.innerWidth;
      target.y = e.clientY / window.innerHeight;
    };

    const tick = () => {
      bgRafRef.current = requestAnimationFrame(tick);
      if (!graphLayerRef.current) return;

      current.x += (target.x - current.x) * LERP;
      current.y += (target.y - current.y) * LERP;

      const dx = (current.x - 0.5) * 6;
      const dy = (current.y - 0.5) * 6;

      graphLayerRef.current.style.backgroundImage = `
        radial-gradient(ellipse 60% 50% at ${15 + dx * 0.5}% ${40 + dy * 0.4}%, rgba(6, 182, 212, 0.07) 0%, transparent 70%),
        radial-gradient(ellipse 50% 60% at ${85 + dx * 0.3}% ${20 + dy * 0.5}%, rgba(139, 92, 246, 0.07) 0%, transparent 60%),
        radial-gradient(ellipse 40% 40% at ${50 + dx * 0.2}% ${80 + dy * 0.2}%, rgba(16, 185, 129, 0.05) 0%, transparent 50%)
      `;

      const gridX = (current.x - 0.5) * 8;
      const gridY = (current.y - 0.5) * 8;
      graphLayerRef.current.style.setProperty('--grid-dx', `${gridX}px`);
      graphLayerRef.current.style.setProperty('--grid-dy', `${gridY}px`);
    };

    window.addEventListener('mousemove', handleMouseMove, { passive: true });
    bgRafRef.current = requestAnimationFrame(tick);

    return () => {
      window.removeEventListener('mousemove', handleMouseMove);
      if (bgRafRef.current) cancelAnimationFrame(bgRafRef.current);
    };
  }, []);

  return graphLayerRef;
}
