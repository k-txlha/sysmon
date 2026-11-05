import { useState } from 'react';
import { Shield } from 'lucide-react';
import { loginAdmin, setupAdmin } from '../api/client';

export default function AuthScreen({ setupRequired, onAuthenticated }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [submitting, setSubmitting] = useState(false);

  const submit = async (event) => {
    event.preventDefault();
    setError('');
    setSubmitting(true);
    try {
      const authenticate = setupRequired ? setupAdmin : loginAdmin;
      const user = await authenticate(username, password);
      onAuthenticated(user);
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <main className="auth-screen">
      <section className="auth-card">
        <div className="auth-brand">
          <div className="sidebar-logo"><Shield /></div>
          <div>
            <h1>Sysmon</h1>
            <p>{setupRequired ? 'Initial administrator setup' : 'Administrator sign in'}</p>
          </div>
        </div>
        {setupRequired && (
          <p className="auth-notice">
            Setup is only available from the backend host. Choose a unique username and a
            password of at least 12 characters.
          </p>
        )}
        <form onSubmit={submit}>
          <label className="form-group">
            <span className="form-label">Username</span>
            <input
              className="form-input"
              autoComplete="username"
              minLength={3}
              maxLength={64}
              value={username}
              onChange={(event) => setUsername(event.target.value)}
              required
            />
          </label>
          <label className="form-group">
            <span className="form-label">Password</span>
            <input
              className="form-input"
              type="password"
              autoComplete={setupRequired ? 'new-password' : 'current-password'}
              minLength={setupRequired ? 12 : 1}
              maxLength={128}
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              required
            />
          </label>
          {error && <p className="auth-error" role="alert">{error}</p>}
          <button className="btn btn-primary auth-submit" type="submit" disabled={submitting}>
            {submitting ? 'Please wait…' : setupRequired ? 'Create administrator' : 'Sign in'}
          </button>
        </form>
      </section>
    </main>
  );
}
