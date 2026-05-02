import React from 'react';

type IconProps = { size?: number; className?: string };

export const ScanIcon: React.FC<IconProps> = ({ size = 14, className }) => (
  <svg width={size} height={size} viewBox="0 0 16 16" fill="none" className={className}>
    <circle cx="8" cy="8" r="2.5" fill="currentColor" />
    <path d="M8 2a6 6 0 1 1 0 12A6 6 0 0 1 8 2Z" stroke="currentColor" strokeWidth="1.2" strokeDasharray="3 2" opacity="0.5" />
    <path d="M8 4.5a3.5 3.5 0 1 1 0 7 3.5 3.5 0 0 1 0-7Z" stroke="currentColor" strokeWidth="1.2" opacity="0.75" />
  </svg>
);

export const HopperIcon: React.FC<IconProps> = ({ size = 14, className }) => (
  <svg width={size} height={size} viewBox="0 0 16 16" fill="none" className={className}>
    <path d="M13 8A5 5 0 0 1 3.5 11.3" stroke="currentColor" strokeWidth="1.3" strokeLinecap="round" />
    <path d="M3 8A5 5 0 0 1 12.5 4.7" stroke="currentColor" strokeWidth="1.3" strokeLinecap="round" />
    <path d="M11 2.5l1.5 2.2-2.2.8" stroke="currentColor" strokeWidth="1.3" strokeLinecap="round" strokeLinejoin="round" />
    <path d="M5 13.5l-1.5-2.2 2.2-.8" stroke="currentColor" strokeWidth="1.3" strokeLinecap="round" strokeLinejoin="round" />
  </svg>
);

export const SignalIcon: React.FC<IconProps> = ({ size = 14, className }) => (
  <svg width={size} height={size} viewBox="0 0 16 16" fill="none" className={className}>
    <rect x="1.5" y="10" width="2" height="4" rx="0.8" fill="currentColor" opacity="0.4" />
    <rect x="5" y="7.5" width="2" height="6.5" rx="0.8" fill="currentColor" opacity="0.6" />
    <rect x="8.5" y="5" width="2" height="9" rx="0.8" fill="currentColor" opacity="0.8" />
    <rect x="12" y="2" width="2" height="12" rx="0.8" fill="currentColor" />
  </svg>
);

export const LockIcon: React.FC<IconProps> = ({ size = 14, className }) => (
  <svg width={size} height={size} viewBox="0 0 16 16" fill="none" className={className}>
    <rect x="3" y="7.5" width="10" height="7" rx="1.5" stroke="currentColor" strokeWidth="1.3" />
    <path d="M5.5 7.5V5.5a2.5 2.5 0 0 1 5 0v2" stroke="currentColor" strokeWidth="1.3" strokeLinecap="round" />
    <circle cx="8" cy="11" r="1.2" fill="currentColor" />
  </svg>
);

export const ChannelIcon: React.FC<IconProps> = ({ size = 14, className }) => (
  <svg width={size} height={size} viewBox="0 0 16 16" fill="none" className={className}>
    <path d="M2 8c1.5-3 3.5-4.5 6-4.5S12.5 5 14 8c-1.5 3-3.5 4.5-6 4.5S3.5 11 2 8Z" stroke="currentColor" strokeWidth="1.3" />
    <circle cx="8" cy="8" r="1.8" fill="currentColor" />
  </svg>
);

export const NodeTypeIcon: React.FC<IconProps> = ({ size = 14, className }) => (
  <svg width={size} height={size} viewBox="0 0 16 16" fill="none" className={className}>
    <circle cx="8" cy="3.5" r="1.8" stroke="currentColor" strokeWidth="1.2" />
    <circle cx="3" cy="12" r="1.8" stroke="currentColor" strokeWidth="1.2" />
    <circle cx="13" cy="12" r="1.8" stroke="currentColor" strokeWidth="1.2" />
    <line x1="8" y1="5.3" x2="3" y2="10.2" stroke="currentColor" strokeWidth="1.1" opacity="0.6" />
    <line x1="8" y1="5.3" x2="13" y2="10.2" stroke="currentColor" strokeWidth="1.1" opacity="0.6" />
  </svg>
);

export const InterfaceIcon: React.FC<IconProps> = ({ size = 14, className }) => (
  <svg width={size} height={size} viewBox="0 0 16 16" fill="none" className={className}>
    <path d="M4 9.5C5.5 7 6.7 6 8 6s2.5 1 4 3.5" stroke="currentColor" strokeWidth="1.3" strokeLinecap="round" />
    <path d="M2 11.5C4 7.5 6 5.5 8 5.5s4 2 6 6" stroke="currentColor" strokeWidth="1.3" strokeLinecap="round" opacity="0.5" />
    <circle cx="8" cy="12" r="1.5" fill="currentColor" />
  </svg>
);

export const PersistIcon: React.FC<IconProps> = ({ size = 14, className }) => (
  <svg width={size} height={size} viewBox="0 0 16 16" fill="none" className={className}>
    <rect x="2.5" y="2.5" width="11" height="11" rx="2" stroke="currentColor" strokeWidth="1.3" />
    <rect x="5" y="2.5" width="6" height="4" rx="0.5" fill="currentColor" opacity="0.4" />
    <rect x="5" y="8.5" width="6" height="4" rx="1" stroke="currentColor" strokeWidth="1.1" />
    <circle cx="10.5" cy="10.5" r="1" fill="currentColor" />
  </svg>
);

export const ClockIcon: React.FC<IconProps> = ({ size = 14, className }) => (
  <svg width={size} height={size} viewBox="0 0 16 16" fill="none" className={className}>
    <circle cx="8" cy="8" r="5.5" stroke="currentColor" strokeWidth="1.3" />
    <path d="M8 5v3.5l2 1.5" stroke="currentColor" strokeWidth="1.3" strokeLinecap="round" strokeLinejoin="round" />
  </svg>
);

export const ChevronIcon: React.FC<{ open: boolean; size?: number }> = ({ open, size = 10 }) => (
  <svg
    className={`panel-chevron ${open ? 'open' : ''}`}
    width={size} height={size} viewBox="0 0 10 10"
    fill="none"
  >
    <path d="M2 3.5L5 6.5L8 3.5" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
  </svg>
);
