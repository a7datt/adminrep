import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { ShieldCheck, Mail, UserPlus, RefreshCw } from 'lucide-react';
import { setAccessToken, scheduleProactiveRefresh } from '../lib/api';

// أيقونة Google SVG
function GoogleIcon() {
  return (
    <svg className="w-5 h-5" viewBox="0 0 24 24">
      <path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/>
      <path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/>
      <path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l3.66-2.84z"/>
      <path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"/>
    </svg>
  );
}

type Step = 'form' | 'otp';

export default function Register() {
  const [step, setStep] = useState<Step>('form');
  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [otpCode, setOtpCode] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [resendCooldown, setResendCooldown] = useState(0);
  const navigate = useNavigate();

  const handleGoogleRegister = () => {
    window.location.href = '/api/auth/google';
  };

  // الخطوة 1: التحقق من البيانات وإرسال OTP
  const handleSendOTP = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      const res = await fetch('/api/auth/register/send-otp', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, email, password }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'فشل إرسال رمز التحقق');
      setStep('otp');
      startResendCooldown();
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  // الخطوة 2: التحقق من OTP وإنشاء الحساب
  const handleVerifyOTP = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      const res = await fetch('/api/auth/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, email, password, otp_code: otpCode }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'فشل إنشاء الحساب');

      // SECURITY: access token stored in memory only — never localStorage.
      // The refresh token lives in an HttpOnly cookie (set by server) and is
      // never accessible to JavaScript, preventing XSS-based token theft.
      setAccessToken(data.token);
      localStorage.setItem('user', JSON.stringify(data.user));
      scheduleProactiveRefresh(data.token);
      navigate('/dashboard');
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleResendOTP = async () => {
    if (resendCooldown > 0) return;
    setError('');
    try {
      const res = await fetch('/api/auth/resend-otp', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, type: 'register' }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'فشل إعادة الإرسال');
      startResendCooldown();
    } catch (err: any) {
      setError(err.message);
    }
  };

  const startResendCooldown = () => {
    setResendCooldown(60);
    const interval = setInterval(() => {
      setResendCooldown((prev) => {
        if (prev <= 1) { clearInterval(interval); return 0; }
        return prev - 1;
      });
    }, 1000);
  };

  return (
    <div className="min-h-screen flex flex-col items-center justify-center bg-gray-50 py-12 px-4 sm:px-6 lg:px-8">
      <div className="max-w-md w-full space-y-8 bg-white p-10 rounded-2xl shadow-sm border border-gray-100">
        <div className="flex flex-col items-center">
          <ShieldCheck className="w-12 h-12 text-primary mb-4" />
          <h2 className="text-center text-3xl font-extrabold text-[#0936AD]">
            إنشاء حساب جديد
          </h2>
          <p className="mt-2 text-center text-sm text-gray-600">
            {step === 'form'
              ? 'أدخل التفاصيل الخاصة بك لإنشاء حساب'
              : 'أدخل رمز التحقق المرسل إلى بريدك الإلكتروني'}
          </p>
        </div>

        {/* زر إنشاء الحساب بجوجل - يظهر في الخطوة الأولى فقط */}
        {step === 'form' && (
          <>
            <button
              type="button"
              onClick={handleGoogleRegister}
              className="w-full flex items-center justify-center gap-3 py-3 px-4 border border-gray-300 rounded-lg text-sm font-medium text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-[#0936AD] transition-colors"
            >
              <GoogleIcon />
              إنشاء حساب بجوجل
            </button>

            <div className="relative">
              <div className="absolute inset-0 flex items-center">
                <div className="w-full border-t border-gray-200" />
              </div>
              <div className="relative flex justify-center text-sm">
                <span className="px-3 bg-white text-gray-400">أو بالبريد الإلكتروني</span>
              </div>
            </div>
          </>
        )}

        {/* مؤشر الخطوات */}
        <div className="flex items-center justify-center gap-3">
          <div className={`flex items-center gap-1.5 text-xs font-medium px-3 py-1.5 rounded-full transition-colors ${step === 'form' ? 'bg-[#0936AD] text-white' : 'bg-green-100 text-green-700'}`}>
            <UserPlus className="w-3 h-3" />
            بيانات الحساب
          </div>
          <div className="w-6 h-0.5 bg-gray-200" />
          <div className={`flex items-center gap-1.5 text-xs font-medium px-3 py-1.5 rounded-full transition-colors ${step === 'otp' ? 'bg-[#0936AD] text-white' : 'bg-gray-100 text-gray-500'}`}>
            <Mail className="w-3 h-3" />
            تأكيد البريد
          </div>
        </div>

        {/* الخطوة 1: بيانات الحساب */}
        {step === 'form' && (
          <form className="mt-2 space-y-6" onSubmit={handleSendOTP}>
            {error && (
              <div className="text-red-500 text-sm text-center bg-red-50 p-3 rounded">
                {error}
              </div>
            )}
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">الاسم الكامل</label>
                <input
                  type="text"
                  required
                  className="appearance-none rounded-lg relative block w-full px-3 py-3 border border-gray-300 placeholder-gray-400 text-[#0936AD] focus:outline-none focus:ring-primary focus:border-primary sm:text-sm"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">البريد الإلكتروني</label>
                <input
                  type="email"
                  required
                  className="appearance-none rounded-lg relative block w-full px-3 py-3 border border-gray-300 placeholder-gray-400 text-[#0936AD] focus:outline-none focus:ring-primary focus:border-primary sm:text-sm text-left"
                  placeholder="name@example.com"
                  dir="ltr"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">كلمة المرور</label>
                <input
                  type="password"
                  required
                  className="appearance-none rounded-lg relative block w-full px-3 py-3 border border-gray-300 placeholder-gray-400 text-[#0936AD] focus:outline-none focus:ring-primary focus:border-primary sm:text-sm text-left"
                  dir="ltr"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                />
                <p className="text-xs text-gray-500 mt-1">8 أحرف على الأقل، حرف كبير، حرف صغير، ورقم</p>
              </div>
            </div>
            <button
              type="submit"
              disabled={loading}
              className="group relative w-full flex justify-center py-3 px-4 border border-transparent text-sm font-bold rounded-lg text-white bg-primary hover:bg-primary-dark focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary transition-colors disabled:opacity-60"
            >
              {loading ? 'جارٍ الإرسال...' : 'إرسال رمز التحقق'}
            </button>
          </form>
        )}

        {/* الخطوة 2: رمز OTP */}
        {step === 'otp' && (
          <form className="mt-2 space-y-6" onSubmit={handleVerifyOTP}>
            {error && (
              <div className="text-red-500 text-sm text-center bg-red-50 p-3 rounded">
                {error}
              </div>
            )}

            <div className="bg-blue-50 border border-blue-100 rounded-lg p-4 text-center">
              <Mail className="w-6 h-6 text-[#0936AD] mx-auto mb-2" />
              <p className="text-sm text-gray-600">تم إرسال رمز التحقق إلى</p>
              <p className="text-sm font-semibold text-[#0936AD] mt-1" dir="ltr">{email}</p>
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">رمز التحقق (6 أرقام)</label>
              <input
                type="text"
                required
                maxLength={6}
                pattern="\d{6}"
                inputMode="numeric"
                className="appearance-none rounded-lg relative block w-full px-3 py-3 border border-gray-300 placeholder-gray-400 text-[#0936AD] focus:outline-none focus:ring-primary focus:border-primary text-2xl font-bold tracking-widest text-center"
                placeholder="000000"
                dir="ltr"
                value={otpCode}
                onChange={(e) => setOtpCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
              />
              <p className="text-xs text-gray-500 mt-1.5 text-center">صالح لمدة 10 دقائق فقط</p>
            </div>

            <button
              type="submit"
              disabled={loading || otpCode.length !== 6}
              className="group relative w-full flex justify-center py-3 px-4 border border-transparent text-sm font-bold rounded-lg text-white bg-primary hover:bg-primary-dark focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary transition-colors disabled:opacity-60"
            >
              {loading ? 'جارٍ إنشاء الحساب...' : 'إنشاء الحساب'}
            </button>

            <div className="flex items-center justify-between text-sm">
              <button
                type="button"
                onClick={() => { setStep('form'); setError(''); setOtpCode(''); }}
                className="text-gray-500 hover:text-primary"
              >
                ← تعديل البيانات
              </button>
              <button
                type="button"
                onClick={handleResendOTP}
                disabled={resendCooldown > 0}
                className="flex items-center gap-1 text-[#0936AD] hover:underline disabled:text-gray-400 disabled:no-underline"
              >
                <RefreshCw className="w-3.5 h-3.5" />
                {resendCooldown > 0 ? `إعادة الإرسال (${resendCooldown}s)` : 'إعادة إرسال الرمز'}
              </button>
            </div>
          </form>
        )}

        <div className="mt-6 text-center">
          <p className="text-sm text-gray-600">
            لديك حساب بالفعل؟{' '}
            <Link to="/login" className="font-medium text-primary hover:underline">
              تسجيل الدخول
            </Link>
          </p>
        </div>
      </div>
    </div>
  );
}
