import type { GraphGroup } from '../types/graph';

export function getRSSILabel(rssi?: number): { label: string; color: string; bars: number } {
  if (rssi === undefined) return { label: 'N/A', color: '#7d92b0', bars: 0 };
  if (rssi >= -55) return { label: 'Excellent', color: '#10b981', bars: 5 };
  if (rssi >= -65) return { label: 'Good',      color: '#10b981', bars: 4 };
  if (rssi >= -75) return { label: 'Fair',       color: '#f59e0b', bars: 3 };
  if (rssi >= -85) return { label: 'Poor',       color: '#ef4444', bars: 2 };
  return              { label: 'Weak',       color: '#ef4444', bars: 1 };
}

export function getTypeColor(group: GraphGroup | string): string {
  switch (group) {
    case 'ap':      return '#06b6d4';
    case 'station': return '#8b5cf6';
    case 'network': return '#10b981';
    default:        return '#7d92b0';
  }
}

export function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(1))} ${sizes[i]}`;
}

export function getGroupLabel(group: GraphGroup | string): string {
  switch (group) {
    case 'ap':      return 'Access Point';
    case 'station': return 'Client Device';
    case 'network': return 'Network Hub';
    default:        return group;
  }
}
