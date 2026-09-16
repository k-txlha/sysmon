import React, { useEffect } from 'react';
import { X } from 'lucide-react';

/**
 * Slide-out detail drawer for displaying JSON / contextual inspection panels.
 *
 * Props:
 *   isOpen: boolean
 *   onClose: () => void
 *   title: string
 *   subtitle?: string
 *   children: ReactNode
 *   width?: string
 */
export default function DetailDrawer({
  isOpen,
  onClose,
  title,
  subtitle,
  children,
  width = '520px',
}) {
  useEffect(() => {
    const handleKeyDown = (e) => {
      if (e.key === 'Escape' && isOpen) {
        onClose();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  return (
    <div className="drawer-overlay" onClick={onClose}>
      <div
        className="drawer-panel"
        style={{ width, maxWidth: '90vw' }}
        onClick={(e) => e.stopPropagation()}
      >
        <div className="drawer-header">
          <div>
            <h3 className="drawer-title">{title}</h3>
            {subtitle && <p className="drawer-subtitle">{subtitle}</p>}
          </div>
          <button
            type="button"
            className="btn-icon drawer-close"
            onClick={onClose}
            aria-label="Close drawer"
          >
            <X size={18} />
          </button>
        </div>
        <div className="drawer-body">{children}</div>
      </div>
    </div>
  );
}
