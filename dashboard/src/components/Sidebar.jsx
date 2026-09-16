import { NavLink, useLocation } from 'react-router-dom';
import {
  LayoutDashboard,
  Monitor,
  ShieldAlert,
  ScrollText,
  BookOpen,
  Settings,
  Shield,
  Activity,
} from 'lucide-react';

const navItems = [
  { label: 'Monitoring', section: true },
  { to: '/', icon: LayoutDashboard, label: 'Overview' },
  { to: '/devices', icon: Monitor, label: 'Devices' },
  { to: '/threats', icon: ShieldAlert, label: 'Threats' },
  { to: '/events', icon: ScrollText, label: 'Events' },
  { label: 'Management', section: true },
  { to: '/rules', icon: BookOpen, label: 'Rules' },
  { to: '/settings', icon: Settings, label: 'Settings' },
];

export default function Sidebar() {
  const location = useLocation();

  return (
    <aside className="sidebar">
      {/* Brand Header */}
      <div className="sidebar-header">
        <div className="sidebar-logo">
          <Shield />
        </div>
        <div className="sidebar-brand">
          <span className="sidebar-brand-name">Sysmon</span>
          <span className="sidebar-brand-tag">Security Platform</span>
        </div>
      </div>

      {/* Navigation Links */}
      <nav className="sidebar-nav">
        {navItems.map((item, i) =>
          item.section ? (
            <div key={i} className="sidebar-section-label">
              {item.label}
            </div>
          ) : (
            <NavLink
              key={item.to}
              to={item.to}
              className={({ isActive }) =>
                `nav-link${isActive ? ' active' : ''}`
              }
              end={item.to === '/'}
            >
              <item.icon />
              <span>{item.label}</span>
            </NavLink>
          )
        )}
      </nav>

      {/* Footer */}
      <div className="sidebar-footer">
        <div className="sidebar-footer-info">
          <span className="dot" />
          <Activity size={13} />
          <span>System Operational</span>
        </div>
      </div>
    </aside>
  );
}
