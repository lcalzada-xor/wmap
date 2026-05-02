import React, { useRef, useCallback, useEffect } from 'react';

interface TiltProps {
  children: React.ReactNode;
  className?: string;
  style?: React.CSSProperties;
  maxRotation?: number; // Rotación máxima en grados
  scale?: number;       // Escala al hacer hover
  perspective?: number; // Distancia de la perspectiva en px
}

export const Tilt: React.FC<TiltProps> = ({
  children,
  className = '',
  style = {},
  maxRotation = 12,
  scale = 1.04,
  perspective = 1000
}) => {
  // Referencias a los elementos del DOM en lugar de usar estado
  const cardRef = useRef<HTMLDivElement>(null);
  const glareRef = useRef<HTMLDivElement>(null);

  // Guardamos el ID del frame para poder cancelarlo y evitar fugas de memoria
  const requestRef = useRef<number | null>(null);

  const onMouseMove = useCallback((e: React.MouseEvent<HTMLDivElement>) => {
    if (!cardRef.current || !glareRef.current) return;

    const { left, top, width, height } = cardRef.current.getBoundingClientRect();

    // Posición relativa del ratón (0 a 1)
    const x = (e.clientX - left) / width;
    const y = (e.clientY - top) / height;

    const rotateY = (x - 0.5) * maxRotation * 2;
    const rotateX = (0.5 - y) * maxRotation * 2;

    // Si ya hay un frame programado, lo cancelamos para no acumular trabajo
    if (requestRef.current) cancelAnimationFrame(requestRef.current);

    // Programamos la actualización visual para el próximo ciclo de repintado
    requestRef.current = requestAnimationFrame(() => {
      if (!cardRef.current || !glareRef.current) return;

      // Manipulación directa del DOM (Cero re-renders en React)
      cardRef.current.style.transform = `perspective(${perspective}px) rotateX(${rotateX}deg) rotateY(${rotateY}deg) scale3d(${scale}, ${scale}, ${scale})`;
      cardRef.current.style.transition = 'none'; // Sin transición para que siga el ratón al instante

      glareRef.current.style.opacity = '0.4';
      glareRef.current.style.top = `${y * 100}%`;
      glareRef.current.style.left = `${x * 100}%`;
      glareRef.current.style.transition = 'none';
    });
  }, [maxRotation, scale, perspective]);

  const onMouseLeave = useCallback(() => {
    if (requestRef.current) cancelAnimationFrame(requestRef.current);

    if (cardRef.current && glareRef.current) {
      cardRef.current.style.transform = `perspective(${perspective}px) rotateX(0deg) rotateY(0deg) scale3d(1, 1, 1)`;
      cardRef.current.style.transition = 'transform 0.6s cubic-bezier(0.23, 1, 0.32, 1)';

      glareRef.current.style.opacity = '0';
      glareRef.current.style.transition = 'opacity 0.6s ease';
    }
  }, [perspective]);

  // Limpieza al desmontar el componente para evitar memory leaks
  useEffect(() => {
    return () => {
      if (requestRef.current) cancelAnimationFrame(requestRef.current);
    };
  }, []);

  return (
    <div
      ref={cardRef}
      className={`tilt-container ${className}`}
      onMouseMove={onMouseMove}
      onMouseLeave={onMouseLeave}
      style={{
        position: 'relative',
        overflow: 'hidden',
        transformStyle: 'preserve-3d',
        willChange: 'transform',
        width: '100%',
        height: '100%',
        transform: `perspective(${perspective}px) rotateX(0deg) rotateY(0deg) scale3d(1, 1, 1)`,
        transition: 'transform 0.5s cubic-bezier(0.23, 1, 0.32, 1)', // Transición inicial por defecto
        ...style
      }}
    >
      <div
        ref={glareRef}
        className="tilt-glare"
        style={{
          opacity: 0,
          transform: 'translate(-50%, -50%)',
          background: 'radial-gradient(circle, rgba(255,255,255,0.15) 0%, rgba(255,255,255,0) 80%)',
          position: 'absolute',
          top: '0%',
          left: '0%',
          width: '150%',
          height: '150%',
          pointerEvents: 'none',
          zIndex: 10,
          borderRadius: '50%',
          filter: 'blur(40px)',
          transition: 'opacity 0.6s ease'
        }}
      />
      <div className="tilt-content" style={{ transformStyle: 'preserve-3d', height: '100%' }}>
        {children}
      </div>
    </div>
  );
};