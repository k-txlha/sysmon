/**
 * Online/offline status indicator.
 * Props:
 *   status – "online" | "offline"
 *   showLabel – if true, renders a text label next to the dot
 */
export default function StatusDot({ status, showLabel = false }) {
  const s = (status || 'offline').toLowerCase();
  if (showLabel) {
    return (
      <span className={`status-badge ${s}`}>
        <span className={`status-dot ${s}`} />
        {s === 'online' ? 'Online' : 'Offline'}
      </span>
    );
  }
  return <span className={`status-dot ${s}`} />;
}
