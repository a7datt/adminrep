import React, { useEffect, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { ShieldCheck, Loader2 } from 'lucide-react';
import { scheduleProactiveRefresh, setAccessToken } from '../lib/api';

export default function GoogleAuthSuccess() {
  const [searchParams] = useSearchParams();
  const [error, setError] = useState('');
  const navigate = useNavigate();

  useEffect(() => {
    const data = searchParams.get('data');
    if (!data) {
      setError('بيانات غير صالحة');
      return;
    }

    try {
      // [HIGH-FIX] The payload now contains only the short-lived access token
      // and user info.  The refresh token is stored in an HttpOnly cookie set
      // by the server and is never accessible to JavaScript.
      const decoded = JSON.parse(atob(decodeURIComponent(data)));
      const { token, email, name } = decoded;

      if (!token) {
        setError('فشل استلام بيانات الجلسة');
        return;
      }

      // SECURITY: access token stored in memory only — never localStorage.
      // The refresh token lives in an HttpOnly cookie (set by server) and is
      // never accessible to JavaScript, preventing XSS-based token theft.
      setAccessToken(token);
      localStorage.setItem('user', JSON.stringify({ email, name }));
      // Start proactive refresh scheduler immediately after Google login
      scheduleProactiveRefresh(token);

      // تنظيف URL فوراً
      window.history.replaceState({}, '', '/dashboard');
      navigate('/dashboard', { replace: true });
    } catch {
      setError('حدث خطأ في معالجة بيانات جوجل');
    }
  }, []);

  if (error) {
    return (
      <div className="min-h-screen flex flex-col items-center justify-center bg-gray-50">
        <div className="bg-white p-10 rounded-2xl shadow-sm border border-gray-100 text-center max-w-sm">
          <p className="text-red-500 mb-4">{error}</p>
          <a href="/login" className="text-[#0936AD] font-medium hover:underline">
            العودة لتسجيل الدخول
          </a>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen flex flex-col items-center justify-center bg-gray-50">
      <div className="bg-white p-10 rounded-2xl shadow-sm border border-gray-100 text-center max-w-sm">
        <ShieldCheck className="w-12 h-12 text-[#0936AD] mx-auto mb-4" />
        <Loader2 className="w-6 h-6 text-[#0936AD] mx-auto mb-3 animate-spin" />
        <p className="text-gray-600 text-sm">جارٍ تسجيل الدخول...</p>
      </div>
    </div>
  );
}
