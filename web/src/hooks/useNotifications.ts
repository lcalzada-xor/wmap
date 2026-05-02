import { useState, useCallback, useRef } from 'react';
import { isWSAlertMessage, isWSLogMessage, type AlertSeverity, type Alert } from '../types/graph';

export interface Notification {
  id: string;
  message: string;
  detail?: string;
  severity: AlertSeverity;
  timestamp: number;
  handshakeFile?: string;
}

const MAX_VISIBLE = 4;
const AUTO_DISMISS_MS = 6000;

function normalizeSeverity(raw: string): AlertSeverity {
  switch (raw.toLowerCase()) {
    case 'critical': return 'critical';
    case 'high':
    case 'error':    return 'error';
    case 'medium':
    case 'warning':
    case 'warn':     return 'warning';
    default:         return 'info';
  }
}

function formatMac(mac?: string): string {
  return mac ? mac.toUpperCase() : '';
}

function buildAlertNotification(alert: Alert): { message: string; detail?: string; severity: AlertSeverity; handshakeFile?: string } {
  const severity = normalizeSeverity(alert.severity);
  const mac = formatMac(alert.device_mac);
  const target = formatMac(alert.target_mac);

  switch (alert.subtype) {
    case 'EVIL_TWIN_DETECTED':
      return {
        severity,
        message: 'Evil Twin detected — security mismatch',
        detail: mac || undefined,
      };
    case 'KARMA_AP_DETECTED':
      return {
        severity,
        message: 'Karma/Mana AP — multiple SSIDs from single BSSID',
        detail: mac || undefined,
      };
    case 'KARMA_DETECTION':
      return {
        severity,
        message: 'Possible Karma attack — excessive probe requests',
        detail: mac || undefined,
      };
    case 'DEAUTH_DETECTED':
      return {
        severity,
        message: 'Deauth/Disassoc frame detected',
        detail: [mac, target ? `→ ${target}` : '', alert.details].filter(Boolean).join('  ') || undefined,
      };
    case 'BROADCAST_DEAUTH':
      return {
        severity,
        message: 'Broadcast deauth attack detected',
        detail: [mac, alert.details].filter(Boolean).join('  ') || undefined,
      };
    case 'OUI_SPOOFING':
      return {
        severity,
        message: 'OUI spoofing — vendor/signature mismatch',
        detail: mac || undefined,
      };
    case 'HIGH_RETRY_RATE':
      return {
        severity,
        message: 'High retry rate anomaly',
        detail: mac || undefined,
      };
    case 'RULE_MATCH':
      return {
        severity,
        message: `Security rule triggered${alert.rule_id ? ` [${alert.rule_id}]` : ''}`,
        detail: mac || undefined,
      };
    case 'WPA_HANDSHAKE':
      return {
        severity: 'warning',
        message: 'WPA handshake captured',
        detail: [alert.details, target ? `STA ${target}` : ''].filter(Boolean).join('  ') || mac || undefined,
        handshakeFile: alert.handshake_file || undefined,
      };
    case 'VULNERABILITY_DETECTED':
      return {
        severity: 'error',
        message: 'PMKID exposure detected',
        detail: alert.details || mac || undefined,
      };
    case 'WEAK_CRYPTO_ZERO_NONCE':
      return {
        severity: 'critical',
        message: 'Critical crypto flaw — zero nonce in handshake',
        detail: alert.details || mac || undefined,
      };
    case 'WEAK_CRYPTO_BAD_RNG':
      return {
        severity: 'error',
        message: 'Weak RNG — repeating nonce pattern',
        detail: alert.details || mac || undefined,
      };
    default:
      return {
        severity,
        message: alert.message,
        detail: mac || undefined,
      };
  }
}

export function useNotifications() {
  const [notifications, setNotifications] = useState<Notification[]>([]);
  const timersRef = useRef<Map<string, ReturnType<typeof setTimeout>>>(new Map());

  const dismiss = useCallback((id: string) => {
    const t = timersRef.current.get(id);
    if (t) { clearTimeout(t); timersRef.current.delete(id); }
    setNotifications(prev => prev.filter(n => n.id !== id));
  }, []);

  const push = useCallback((entry: Omit<Notification, 'id' | 'timestamp'>) => {
    const id = `${Date.now()}-${Math.random().toString(36).slice(2, 7)}`;
    const notification: Notification = { ...entry, id, timestamp: Date.now() };

    setNotifications(prev => {
      const next = [notification, ...prev].slice(0, MAX_VISIBLE);
      prev.slice(MAX_VISIBLE - 1).forEach(n => {
        const t = timersRef.current.get(n.id);
        if (t) { clearTimeout(t); timersRef.current.delete(n.id); }
      });
      return next;
    });

    const t = setTimeout(() => dismiss(id), AUTO_DISMISS_MS);
    timersRef.current.set(id, t);
  }, [dismiss]);

  const handleWSMessage = useCallback((msg: unknown) => {
    if (isWSAlertMessage(msg)) {
      push(buildAlertNotification(msg.payload));
    } else if (isWSLogMessage(msg)) {
      push({
        message: msg.payload.message,
        severity: normalizeSeverity(msg.payload.level),
      });
    }
  }, [push]);

  return { notifications, dismiss, handleWSMessage };
}
