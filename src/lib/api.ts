// [FIX] Proactive token refresh: renews the access token ~2 minutes before expiry
// so the user never hits a 401 mid-session. Reactive refresh is kept as a fallback.

// ─────────────────────────────────────────────
// JWT helpers (no external dependency needed — we only read the exp claim)
// ─────────────────────────────────────────────
function getTokenExpiry(token: string): number | null {
  try {
    const payload = JSON.parse(atob(token.split('.')[1]));
    return typeof payload.exp === 'number' ? payload.exp * 1000 : null; // convert to ms
  } catch {
    return null;
  }
}

// ─────────────────────────────────────────────
// Proactive refresh scheduler
// Schedules a silent refresh 2 minutes before the access token expires.
// Call this once after login / after every refresh.
// ─────────────────────────────────────────────
let _proactiveRefreshTimer: ReturnType<typeof setTimeout> | null = null;

export function scheduleProactiveRefresh(token: string): void {
  if (_proactiveRefreshTimer) {
    clearTimeout(_proactiveRefreshTimer);
    _proactiveRefreshTimer = null;
  }

  const expiry = getTokenExpiry(token);
  if (!expiry) return;

  const msUntilExpiry = expiry - Date.now();
  // Refresh 2 minutes (120 000 ms) before expiry; if already close, refresh in 5 s
  const delay = Math.max(msUntilExpiry - 2 * 60 * 1000, 5000);

  _proactiveRefreshTimer = setTimeout(async () => {
    try {
      const refreshRes = await fetch('/api/auth/refresh', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({}),
      });

      if (refreshRes.ok) {
        const data = await refreshRes.json();
        localStorage.setItem('token', data.token);
        // Schedule next proactive refresh for the new token
        scheduleProactiveRefresh(data.token);
      } else {
        // Refresh failed — clear session and redirect to login
        localStorage.removeItem('token');
        localStorage.removeItem('user');
        window.location.href = '/login';
      }
    } catch {
      // Network error — will be caught reactively on next API call
    }
  }, delay);
}

// ─────────────────────────────────────────────
// Core fetch wrapper
// [HIGH-FIX] The refresh token is stored exclusively in an HttpOnly cookie.
// JavaScript never reads or stores the refresh token.
// The /api/auth/refresh endpoint reads the cookie automatically.
// ─────────────────────────────────────────────
export async function fetchApi(
  endpoint: string,
  options: RequestInit = {},
  _retry = false
): Promise<Response> {
  const token = localStorage.getItem('token');

  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(options.headers as Record<string, string> || {}),
  };

  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  const response = await fetch(endpoint, {
    ...options,
    headers,
    // credentials: 'include' is required so the HttpOnly refresh-token
    // cookie is sent with same-origin requests to /api/auth/refresh.
    credentials: 'include',
  });

  // ── Reactive refresh fallback (in case proactive refresh missed) ──
  if (response.status === 401 && !_retry) {
    try {
      const refreshRes = await fetch('/api/auth/refresh', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({}),
      });

      if (refreshRes.ok) {
        const data = await refreshRes.json();
        localStorage.setItem('token', data.token);
        // Re-arm the proactive scheduler with the new token
        scheduleProactiveRefresh(data.token);
        return fetchApi(endpoint, options, true);
      }
    } catch {
      // Refresh failed — fall through to session expiry handling
    }

    localStorage.removeItem('token');
    localStorage.removeItem('user');
    window.location.href = '/login';
    throw new Error('Session expired');
  }

  if (response.status === 403) {
    const errorData = await response.clone().json().catch(() => null);
    if (errorData && errorData.error === 'SUBSCRIPTION_EXPIRED') {
      window.location.href = '/dashboard/subscription';
      throw new Error('اشتراكك منتهي، يرجى التجديد');
    }
    throw new Error('Unauthorized access');
  }

  return response;
}
