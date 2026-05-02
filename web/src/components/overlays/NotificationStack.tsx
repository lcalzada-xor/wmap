import type { Notification } from '../../hooks/useNotifications';
import type { AlertSeverity } from '../../types/graph';
import './NotificationStack.css';

interface Props {
  notifications: Notification[];
  onDismiss: (id: string) => void;
}

const ICONS: Record<AlertSeverity, string> = {
  info:     '○',
  warning:  '△',
  error:    '⊗',
  critical: '⬡',
};

export function NotificationStack({ notifications, onDismiss }: Props) {
  if (notifications.length === 0) return null;

  return (
    <div className="notif-stack" role="log" aria-live="polite" aria-label="Notifications">
      {notifications.map((n) => (
        <div key={n.id} className={`notif-item notif-${n.severity}`} role="alert">
          <span className="notif-icon" aria-hidden="true">{ICONS[n.severity]}</span>
          <span className="notif-body">
            <span className="notif-msg">{n.message}</span>
            {n.detail && <span className="notif-detail">{n.detail}</span>}
            {n.handshakeFile && (
              <span
                className="notif-file"
                title={n.handshakeFile}
                onClick={() => navigator.clipboard.writeText(n.handshakeFile!)}
              >
                {n.handshakeFile.split('/').pop()}
              </span>
            )}
          </span>
          <button
            className="notif-close"
            onClick={() => onDismiss(n.id)}
            aria-label="Dismiss notification"
          >
            ×
          </button>
        </div>
      ))}
    </div>
  );
}
