import { useEffect, useState } from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import Layout from './components/Layout';
import AuthScreen from './pages/AuthScreen';
import Overview from './pages/Overview';
import Devices from './pages/Devices';
import Threats from './pages/Threats';
import Events from './pages/Events';
import Rules from './pages/Rules';
import Settings from './pages/Settings';
import { getAuthStatus, getCurrentAdmin, logoutAdmin } from './api/client';

export default function App() {
  const [auth, setAuth] = useState({ loading: true, setupRequired: false, user: null, error: '' });

  useEffect(() => {
    let active = true;
    const expireSession = () => {
      setAuth({ loading: false, setupRequired: false, user: null, error: '' });
    };
    window.addEventListener('sysmon-auth-expired', expireSession);
    const initialize = async () => {
      try {
        const status = await getAuthStatus();
        if (!active) return;
        if (status.setup_required) {
          setAuth({ loading: false, setupRequired: true, user: null, error: '' });
          return;
        }
        try {
          const user = await getCurrentAdmin();
          if (active) setAuth({ loading: false, setupRequired: false, user, error: '' });
        } catch (error) {
          if (active && error.message !== 'Administrator authentication required.') {
            setAuth({ loading: false, setupRequired: false, user: null, error: error.message });
          } else if (active) {
            setAuth({ loading: false, setupRequired: false, user: null, error: '' });
          }
        }
      } catch (error) {
        if (active) setAuth({ loading: false, setupRequired: false, user: null, error: error.message });
      }
    };
    initialize();
    return () => {
      active = false;
      window.removeEventListener('sysmon-auth-expired', expireSession);
    };
  }, []);

  const signOut = async () => {
    try {
      await logoutAdmin();
      setAuth((current) => ({ ...current, user: null }));
    } catch (error) {
      setAuth({
        loading: false,
        setupRequired: false,
        user: null,
        error: `Sign out failed: ${error.message}`,
      });
    }
  };

  if (auth.loading) return <main className="auth-screen"><p>Loading Sysmon…</p></main>;
  if (auth.error) return <main className="auth-screen"><p className="auth-error">{auth.error}</p></main>;
  if (!auth.user) {
    return (
      <AuthScreen
        setupRequired={auth.setupRequired}
        onAuthenticated={(user) => setAuth({ loading: false, setupRequired: false, user, error: '' })}
      />
    );
  }

  return (
    <BrowserRouter>
      <Routes>
        <Route element={<Layout onLogout={signOut} />}>
          <Route index element={<Overview />} />
          <Route path="devices" element={<Devices />} />
          <Route path="threats" element={<Threats />} />
          <Route path="events" element={<Events />} />
          <Route path="rules" element={<Rules />} />
          <Route path="settings" element={<Settings />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}
