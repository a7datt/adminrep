// ─────────────────────────────────────────────
// SECURITY: Access token is stored in memory only (never localStorage).
//
// WHY: localStorage is readable by any JavaScript on the page. If an XSS
// vulnerability exists anywhere in the app, an attacker can steal the token
// with a single `localStorage.getItem('token')` call.
//
// HOW: The token is held in a module-level variable. It lives as long as
// the tab is open. On tab close/refresh the token is gone — but the
// HttpOnly refresh cookie (30-day lifetime, set by the server) silently
// restores the session on the next load via silentRefresh().
// ─────────────────────────────────────────────

// In-memory access token — never written to localStorage / sessionStorage
let _accessToken: string | null = null;

/** Read the in-memory access token (used by fetchApi and ProtectedRoute). */
export function getAccessToken(): string | null {
  return _accessToken;
}

/** Set the in-memory access token (called after login / refresh). */
export function setAccessToken(token: string | null): void {
  _accessToken = token;
}

/** Clear the in-memory access token (called on logout or session expiry). */
export function clearAccessToken(): void {
  _accessToken = null;
}

// ─────────────────────────────────────────────
// JWT helpers
// ─────────────────────────────────────────────
function getTokenExpiry(token: string): number | null {
  try {
    const payload = JSON.parse(atob(token.split('.')[1]));
    return typeof payload.exp === 'number' ? payload.exp * 1000 : null;
  } catch {
    return null;
  }
}

function isTokenExpiredOrClose(token: string, bufferMs = 60_000): boolean {
  const expiry = getTokenExpiry(token);
  if (!expiry) return true;
  return Date.now() >= expiry - bufferMs;
}

// ─────────────────────────────────────────────
// Proactive refresh scheduler
// Schedules a silent refresh 2 minutes before the access token expires.
// Resets itself on every successful refresh.
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
  const delay = Math.max(msUntilExpiry - 2 * 60 * 1000, 5_000);

  _proactiveRefreshTimer = setTimeout(async () => {
    try {
      const newToken = await doRefresh();
      if (newToken) {
        scheduleProactiveRefresh(newToken);
      }
    } catch {
      // Network error — will be caught reactively on next API call
    }
  }, delay);
}

// ─────────────────────────────────────────────
// Core refresh logic (shared by proactive + reactive paths)
// Returns new access token on success, null on failure.
// ─────────────────────────────────────────────
async function doRefresh(): Promise<string | null> {
  try {
    const refreshRes = await fetch('/api/auth/refresh', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include', // sends the HttpOnly refresh cookie automatically
      body: JSON.stringify({}),
    });

    if (refreshRes.ok) {
      const data = await refreshRes.json();
      // SECURITY: store the new token in memory only — never localStorage
      setAccessToken(data.token);
      return data.token as string;
    }
  } catch {
    // Network failure — caller decides what to do
  }
  return null;
}

// ─────────────────────────────────────────────
// silentRefresh
// Call this on app startup (before any protected API call).
// If the in-memory token is missing or close to expiry, it silently
// refreshes using the HttpOnly refresh cookie — so the user never sees
// a 401 after returning to the tab hours later.
//
// Returns true  → session is valid (token was fresh or successfully renewed)
// Returns false → session is gone (refresh token expired/revoked)
// ─────────────────────────────────────────────
let _refreshInFlight: Promise<boolean> | null = null;

export async function silentRefresh(): Promise<boolean> {
  // Deduplicate concurrent calls (e.g. multiple components mounting at once)
  if (_refreshInFlight) return _refreshInFlight;

  _refreshInFlight = (async () => {
    const token = getAccessToken();

    // Token still valid with >1 min buffer → nothing to do
    if (token && !isTokenExpiredOrClose(token, 60_000)) {
      scheduleProactiveRefresh(token);
      return true;
    }

    // Token missing or expired → try to refresh silently via HttpOnly cookie
    const newToken = await doRefresh();
    if (newToken) {
      scheduleProactiveRefresh(newToken);
      return true;
    }

    // Refresh failed → clear any stale user info from localStorage
    clearAccessToken();
    localStorage.removeItem('user');
    return false;
  })();

  try {
    return await _refreshInFlight;
  } finally {
    _refreshInFlight = null;
  }
}

// ─────────────────────────────────────────────
// Core fetch wrapper
// Automatically attaches the in-memory access token and handles reactive
// refresh on 401 as a last-resort fallback.
// ─────────────────────────────────────────────
export async function fetchApi(
  endpoint: string,
  options: RequestInit = {},
  _retry = false
): Promise<Response> {
  // SECURITY: read token from memory, not localStorage
  const token = getAccessToken();

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
    credentials: 'include',
  });

  // ── Reactive refresh fallback (covers edge cases the proactive timer missed) ──
  if (response.status === 401 && !_retry) {
    const newToken = await doRefresh();
    if (newToken) {
      scheduleProactiveRefresh(newToken);
      return fetchApi(endpoint, options, true);
    }

    clearAccessToken();
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
