/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useEffect, useState } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { Toaster } from 'react-hot-toast';
import Landing from './pages/Landing';
import Login from './pages/Login';
import Register from './pages/Register';
import GoogleAuthSuccess from './pages/GoogleAuthSuccess';
import DashboardLayout from './pages/DashboardLayout';
import Wallets from './pages/Wallets';
import WalletDetails from './pages/WalletDetails';
import Deposit from './pages/Deposit';
import Subscription from './pages/Subscription';
import ApiKeys from './pages/ApiKeys';
import Docs from './pages/Docs';
import { silentRefresh, getAccessToken } from './lib/api';

class ErrorBoundary extends React.Component<{children: React.ReactNode}, {hasError: boolean}> {
  constructor(props: {children: React.ReactNode}) {
    super(props);
    this.state = { hasError: false };
  }
  static getDerivedStateFromError() { return { hasError: true }; }
  render() {
    if (this.state.hasError) {
      return <div className="p-8 text-center"><h2 className="text-2xl font-bold">حدث خطأ ما.</h2><button onClick={() => window.location.reload()} className="mt-4 text-blue-600 underline">إعادة تحميل الصفحة</button></div>;
    }
    return this.props.children;
  }
}

// ─────────────────────────────────────────────
// ProtectedRoute — smart session guard
//
// Problem: The access token lives 15 minutes. When the user returns after
// hours/days, the token in localStorage is expired. A plain token-existence
// check lets them "in" but every API call immediately fails with 401,
// causing "فشل جلب الحسابات / فشل جلب البيانات".
//
// Fix: Before rendering any protected page we call silentRefresh() which:
//   1. Checks if the stored token is still valid (>1 min left) → proceed.
//   2. If expired → calls /api/auth/refresh using the HttpOnly refresh cookie
//      (valid 7 days) → gets a fresh access token → proceed.
//   3. If refresh also fails (cookie expired/revoked) → redirect to /login.
//
// While the check is running we show nothing (or a tiny spinner) to avoid
// a flash of the dashboard with stale data.
// ─────────────────────────────────────────────
type AuthState = 'checking' | 'authenticated' | 'unauthenticated';

function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const [authState, setAuthState] = useState<AuthState>('checking');

  useEffect(() => {
    let cancelled = false;

    // SECURITY: token is no longer in localStorage. We always call silentRefresh()
    // which either validates the in-memory token or exchanges the HttpOnly
    // refresh cookie for a new access token. No localStorage check needed.
    silentRefresh().then((valid) => {
      if (!cancelled) {
        setAuthState(valid ? 'authenticated' : 'unauthenticated');
      }
    });

    return () => { cancelled = true; };
  }, []);

  if (authState === 'checking') {
    // Minimal loading state — avoids flashing protected content or login page
    return (
      <div className="flex items-center justify-center min-h-screen bg-gray-50">
        <div className="w-8 h-8 border-4 border-blue-600 border-t-transparent rounded-full animate-spin" />
      </div>
    );
  }

  if (authState === 'unauthenticated') {
    return <Navigate to="/login" replace />;
  }

  return <>{children}</>;
}

function AuthRoute({ children }: { children: React.ReactNode }) {
  // SECURITY: check in-memory token, not localStorage
  const token = getAccessToken();
  if (token) return <Navigate to="/dashboard" replace />;
  return <>{children}</>;
}

const NotFound = () => (
  <div className="flex flex-col items-center justify-center min-h-screen">
    <h1 className="text-6xl font-bold mb-4">404</h1>
    <p className="mb-4">الصفحة غير موجودة</p>
    <a href="/" className="text-blue-600 underline">العودة للرئيسية</a>
  </div>
);

export default function App() {
  return (
    <ErrorBoundary>
      <Router>
        <Toaster position="top-center" />
        <Routes>
          <Route path="/" element={<Landing />} />
          <Route path="/login" element={<AuthRoute><Login /></AuthRoute>} />
          <Route path="/register" element={<AuthRoute><Register /></AuthRoute>} />

          {/* صفحة استقبال Google OAuth */}
          <Route path="/auth/google/success" element={<GoogleAuthSuccess />} />

          {/* Dashboard Routes */}
          <Route path="/dashboard" element={<ProtectedRoute><DashboardLayout /></ProtectedRoute>}>
            <Route index element={<Navigate to="wallets" replace />} />
            <Route path="wallets" element={<Wallets />} />
            <Route path="wallets/:walletId" element={<WalletDetails />} />
            <Route path="deposit" element={<Deposit />} />
            <Route path="subscription" element={<Subscription />} />
            <Route path="api-keys" element={<ApiKeys />} />
            <Route path="docs" element={<Docs />} />
          </Route>

          <Route path="*" element={<NotFound />} />
        </Routes>
      </Router>
    </ErrorBoundary>
  );
}
