import { Outlet } from 'react-router-dom';
import Sidebar from './Sidebar';

export default function Layout({ onLogout }) {
  return (
    <div className="app-layout">
      <Sidebar onLogout={onLogout} />
      <main className="main-content">
        <Outlet />
      </main>
    </div>
  );
}
