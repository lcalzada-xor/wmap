import React, { useState, useRef, useEffect, useCallback } from 'react';

interface SelectOption<T extends string | number> {
  value: T;
  label: string;
  sublabel?: string;
}

interface SelectProps<T extends string | number> {
  options: SelectOption<T>[];
  value: T | null;
  onChange: (value: T) => void;
  placeholder?: string;
  icon?: React.ReactNode;
  disabled?: boolean;
}

export function Select<T extends string | number>({
  options,
  value,
  onChange,
  placeholder = 'Select…',
  icon,
  disabled = false,
}: SelectProps<T>) {
  const [open, setOpen] = useState(false);
  const [focusedIdx, setFocusedIdx] = useState(-1);
  const containerRef = useRef<HTMLDivElement>(null);

  const selected = options.find(o => o.value === value) ?? null;

  const close = useCallback(() => {
    setOpen(false);
    setFocusedIdx(-1);
  }, []);

  useEffect(() => {
    if (!open) return;
    const handler = (e: MouseEvent) => {
      if (containerRef.current && !containerRef.current.contains(e.target as Node)) {
        close();
      }
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, [open, close]);

  function handleKeyDown(e: React.KeyboardEvent) {
    if (disabled) return;
    if (!open) {
      if (e.key === 'Enter' || e.key === ' ' || e.key === 'ArrowDown') {
        e.preventDefault();
        setOpen(true);
        setFocusedIdx(0);
      }
      return;
    }
    if (e.key === 'Escape') { close(); return; }
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      setFocusedIdx(i => Math.min(i + 1, options.length - 1));
    }
    if (e.key === 'ArrowUp') {
      e.preventDefault();
      setFocusedIdx(i => Math.max(i - 1, 0));
    }
    if (e.key === 'Enter' && focusedIdx >= 0) {
      e.preventDefault();
      onChange(options[focusedIdx].value);
      close();
    }
  }

  return (
    <div
      ref={containerRef}
      className={`custom-select ${open ? 'open' : ''} ${disabled ? 'disabled' : ''}`}
      onKeyDown={handleKeyDown}
    >
      <button
        className="custom-select-trigger"
        onClick={() => !disabled && setOpen(o => !o)}
        type="button"
        aria-haspopup="listbox"
        aria-expanded={open}
        disabled={disabled}
      >
        {icon && <span className="custom-select-icon">{icon}</span>}
        <span className={`custom-select-value ${!selected ? 'placeholder' : ''}`}>
          {selected ? selected.label : placeholder}
        </span>
        <svg className="custom-select-chevron" width="10" height="10" viewBox="0 0 10 10" fill="none">
          <path d="M2 3.5L5 6.5L8 3.5" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
      </button>

      {open && (
        <div className="custom-select-dropdown" role="listbox">
          {options.map((opt, idx) => (
            <button
              key={String(opt.value)}
              role="option"
              aria-selected={opt.value === value}
              className={`custom-select-option ${opt.value === value ? 'selected' : ''} ${idx === focusedIdx ? 'focused' : ''}`}
              onMouseEnter={() => setFocusedIdx(idx)}
              onMouseDown={e => e.preventDefault()}
              onClick={() => { onChange(opt.value); close(); }}
              type="button"
            >
              <span className="custom-select-option-label">{opt.label}</span>
              {opt.sublabel && <span className="custom-select-option-sub">{opt.sublabel}</span>}
              {opt.value === value && (
                <svg className="custom-select-check" width="10" height="10" viewBox="0 0 10 10" fill="none">
                  <path d="M1.5 5L4 7.5L8.5 2.5" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
                </svg>
              )}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
