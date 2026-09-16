import { AlertTriangle, AlertCircle, Info, AlertOctagon } from 'lucide-react';

const icons = {
  CRITICAL: AlertOctagon,
  HIGH: AlertTriangle,
  MEDIUM: AlertCircle,
  LOW: Info,
};

/**
 * Severity pill badge with icon and color coding.
 * Props: severity – "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
 */
export default function SeverityBadge({ severity }) {
  const key = (severity || 'LOW').toUpperCase();
  const Icon = icons[key] || Info;
  return (
    <span className={`severity-badge ${key.toLowerCase()}`}>
      <Icon size={12} />
      {key}
    </span>
  );
}
