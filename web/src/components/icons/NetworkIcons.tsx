import React from 'react';

export const AccessPointIcon: React.FC<{ color: string; size?: number }> = ({ color, size = 20 }) => (
  <svg width={size} height={size} viewBox="0 0 64 64" fill="none" xmlns="http://www.w3.org/2000/svg">
    <path d="M14 28C18.2 21.4 24.7 17 32 17C39.3 17 45.8 21.4 50 28" stroke={color} strokeWidth="3.5" strokeLinecap="round"/>
    <path d="M20 33C22.9 28.3 27.1 25 32 25C36.9 25 41.1 28.3 44 33" stroke={color} strokeWidth="3.5" strokeLinecap="round"/>
    <path d="M26 38C27.7 35.2 29.7 33.5 32 33.5C34.3 33.5 36.3 35.2 38 38" stroke={color} strokeWidth="3.5" strokeLinecap="round"/>
    <circle cx="32" cy="43" r="3.5" fill={color}/>
    <line x1="32" y1="43" x2="32" y2="48" stroke={color} strokeWidth="3" strokeLinecap="round"/>
    <rect x="20" y="48" width="24" height="4" rx="2" fill={color} fillOpacity="0.8"/>
  </svg>
);

export const StationIcon: React.FC<{ color: string; size?: number }> = ({ color, size = 20 }) => (
  <svg width={size} height={size} viewBox="0 0 64 64" fill="none" xmlns="http://www.w3.org/2000/svg">
    <rect x="13" y="14" width="38" height="26" rx="3" stroke={color} strokeWidth="2.5"/>
    <line x1="19" y1="22" x2="37" y2="22" stroke={color} strokeWidth="1.5" strokeLinecap="round" opacity="0.7"/>
    <line x1="19" y1="27" x2="33" y2="27" stroke={color} strokeWidth="1.5" strokeLinecap="round" opacity="0.7"/>
    <line x1="13" y1="40" x2="51" y2="40" stroke={color} strokeWidth="2.5" strokeLinecap="round"/>
    <path d="M8 40 L11 47 H53 L56 40" stroke={color} strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"/>
  </svg>
);

export const NetworkIcon: React.FC<{ color: string; size?: number }> = ({ color, size = 20 }) => (
  <svg width={size} height={size} viewBox="0 0 64 64" fill="none" xmlns="http://www.w3.org/2000/svg">
    <polygon points="32,8 54,20 54,44 32,56 10,44 10,20" stroke={color} strokeWidth="2.5" strokeLinejoin="round"/>
    <circle cx="32" cy="32" r="5" fill={color}/>
    <line x1="32" y1="27" x2="32" y2="11" stroke={color} strokeWidth="1.5" opacity="0.7"/>
    <line x1="36.3" y1="29.5" x2="51" y2="21" stroke={color} strokeWidth="1.5" opacity="0.7"/>
    <line x1="36.3" y1="34.5" x2="51" y2="43" stroke={color} strokeWidth="1.5" opacity="0.7"/>
    <line x1="32" y1="37" x2="32" y2="53" stroke={color} strokeWidth="1.5" opacity="0.7"/>
    <line x1="27.7" y1="34.5" x2="13" y2="43" stroke={color} strokeWidth="1.5" opacity="0.7"/>
    <line x1="27.7" y1="29.5" x2="13" y2="21" stroke={color} strokeWidth="1.5" opacity="0.7"/>
  </svg>
);

export const WMAPLogo: React.FC<{ size?: number }> = ({ size = 28 }) => (
  <svg 
    width={size} 
    height={size} 
    viewBox="0 0 64 64" 
    fill="none" 
    xmlns="http://www.w3.org/2000/svg"
    aria-hidden="true"
  >
    <path d="M14 28C18.2 21.4 24.7 17 32 17C39.3 17 45.8 21.4 50 28" stroke="#06b6d4" strokeWidth="3.5" strokeLinecap="round"/>
    <path d="M20 33C22.9 28.3 27.1 25 32 25C36.9 25 41.1 28.3 44 33" stroke="#06b6d4" strokeWidth="3.5" strokeLinecap="round"/>
    <path d="M26 38C27.7 35.2 29.7 33.5 32 33.5C34.3 33.5 36.3 35.2 38 38" stroke="#06b6d4" strokeWidth="3.5" strokeLinecap="round"/>
    <circle cx="32" cy="43" r="3.5" fill="#06b6d4"/>
  </svg>
);
