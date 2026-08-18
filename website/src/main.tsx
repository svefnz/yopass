import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import '@shared/styles/index.css';
import '@shared/lib/i18n';
import App from '@app/App.tsx';
import { ConfigProvider } from '@shared/context/ConfigContext';
import { ThemeProvider } from '@shared/theme/ThemeProvider';
import { AuthProvider } from '@shared/context/AuthProvider';

// TOTP gate login continuation: after a successful login the server redirects
// to the server-visible path only (often "/"), because the original deep
// link — e.g. /#/s/{uuid}/{key} — lives in the URL fragment that browsers
// never send to the server. The gate's login page snapshots the visitor's
// full URL into sessionStorage ('yopass_totp_next'); restore it here before
// the first render so users land back on the secret they opened.
// eslint-disable-next-line no-undef -- sessionStorage is a browser global
const totpNext = sessionStorage.getItem('yopass_totp_next');
if (totpNext) {
  sessionStorage.removeItem('yopass_totp_next');
  window.location.replace(totpNext);
}

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <ConfigProvider>
      <ThemeProvider>
        <AuthProvider>
          <App />
        </AuthProvider>
      </ThemeProvider>
    </ConfigProvider>
  </StrictMode>,
);
