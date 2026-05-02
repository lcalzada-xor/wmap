import React, { useState } from 'react';
import { ChevronIcon } from '../icons/PanelIcons';

interface CollapsibleProps {
  label: string;
  icon?: React.ReactNode;
  badge?: React.ReactNode;
  defaultOpen?: boolean;
  children: React.ReactNode;
}

export const Collapsible: React.FC<CollapsibleProps> = ({
  label,
  icon,
  badge,
  defaultOpen = true,
  children,
}) => {
  const [open, setOpen] = useState(defaultOpen);

  return (
    <div className="collapsible-section">
      <button className="collapsible-toggle" onClick={() => setOpen(o => !o)}>
        {icon && <span className="collapsible-icon">{icon}</span>}
        <span className="collapsible-label">{label}</span>
        {badge}
        <ChevronIcon open={open} />
      </button>
      {open && <div className="collapsible-body">{children}</div>}
    </div>
  );
};
