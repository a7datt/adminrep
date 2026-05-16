import { Outlet, NavLink, useNavigate } from 'react-router-dom';
import { Wallet, Key, Book, LogOut, CreditCard, Download, Menu, X } from 'lucide-react';
import { useEffect, useState } from 'react';
import { Logo } from '../components/Logo';
import { fetchApi, scheduleProactiveRefresh, getAccessToken, clearAccessToken } from '../lib/api';

export default function DashboardLayout() {
  const navigate = useNavigate();
  const [user, setUser] = useState<{email: string, name: string} | null>(null);
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);
  const [subData, setSubData] = useState<any>(null);

  useEffect(() => {
    // SECURITY: token is in memory (not localStorage). If missing, the
    // HttpOnly refresh cookie will restore the session via ProtectedRoute's
    // silentRefresh(). If both are gone, redirect to login.
    const token = getAccessToken();
    const userStr = localStorage.getItem('user');
    if (!token || !userStr) {
      navigate('/login');
      return;
    }
    setUser(JSON.parse(userStr));

    // Start proactive token refresh so the session never expires silently
    scheduleProactiveRefresh(token);

    // Use fetchApi (not raw fetch) so 401 triggers automatic token refresh
    fetchApi('/api/dashboard/subscription')
      .then(res => res.json())
      .then(data => {
        if (!data.error) setSubData(data);
      })
      .catch(console.error);
  }, [navigate]);

  const handleLogout = async () => {
    try {
      // [FIX] Revoke the refresh token on the server before clearing local state
      await fetch('/api/auth/logout', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({}),
      });
    } catch {
      // Ignore network errors on logout — still clear local session
    }
    // SECURITY: clear in-memory token + user display info
    clearAccessToken();
    localStorage.removeItem('user');
    navigate('/login');
  };

  const navItems = [
    { name: 'المحافظ', path: '/dashboard/wallets', icon: Wallet },
    { name: 'الاشتراك', path: '/dashboard/subscription', icon: CreditCard },
    { name: 'إيداع رصيد', path: '/dashboard/deposit', icon: Download },
    { name: 'مفاتيح API', path: '/dashboard/api-keys', icon: Key },
    { name: 'توثيق API', path: '/dashboard/docs', icon: Book },
  ];

  if (!user) return null;

  return (
    <div className="flex h-screen bg-gray-50 flex-col md:flex-row">
      {/* Mobile Header */}
      <div className="md:hidden flex items-center justify-between p-4 bg-white border-b border-gray-200 z-20 sticky top-0">
         <div className="text-xl font-bold flex items-center gap-2">
            <Logo className="w-8 h-8 rounded" />
            SYB API
         </div>
         <button onClick={() => setIsMobileMenuOpen(!isMobileMenuOpen)} className="p-2 -mr-2 text-gray-600 hover:text-primary">
            {isMobileMenuOpen ? <X className="w-6 h-6" /> : <Menu className="w-6 h-6" />}
         </button>
      </div>

      {/* Mobile Menu Overlay */}
      {isMobileMenuOpen && (
        <div 
          className="fixed inset-0 bg-primary/50 z-30 md:hidden" 
          onClick={() => setIsMobileMenuOpen(false)}
        />
      )}

      {/* Sidebar (Right side for RTL) */}
      <aside className={`fixed inset-y-0 right-0 z-40 w-64 bg-white border-l border-gray-200 flex flex-col transition-transform duration-300 md:static md:translate-x-0 ${isMobileMenuOpen ? 'translate-x-0' : 'translate-x-full'}`}>
        <div className="p-6 hidden md:block border-b border-gray-100">
          <div className="text-xl font-bold flex items-center gap-2 mb-2">
            <Logo className="w-8 h-8 rounded" />
            SYB API
          </div>
          <div className="text-sm text-gray-500 font-mono mb-4" dir="ltr" style={{textAlign: 'right'}}>{user.email}</div>
          
          {subData && (
             <div className="bg-gray-50 rounded-lg p-3 border border-gray-100 space-y-2">
               <div className="flex justify-between items-center">
                 <span className="text-xs text-gray-500">الرصيد:</span>
                 <span className="font-bold font-mono text-primary text-sm">${Number(subData.current_balance || 0).toFixed(2)}</span>
               </div>
               <div className="flex justify-between items-center">
                 <span className="text-xs text-gray-500">الاشتراك:</span>
                 <span className="font-medium text-xs text-gray-700 bg-gray-200 px-2 py-0.5 rounded">
                   {(() => {
                      if (!subData.expires_at) return 'غير محدود';
                      const diffMs = new Date(subData.expires_at).getTime() - Date.now();
                      if (diffMs <= 0) return 'منتهي';
                      const diffDays = Math.floor(diffMs / (1000 * 60 * 60 * 24));
                      if (diffDays >= 30) return `${Math.floor(diffDays / 30)} شهر`;
                      if (diffDays >= 1) return `${diffDays} يوم`;
                      const diffHours = Math.floor(diffMs / (1000 * 60 * 60));
                      if (diffHours >= 1) return `${diffHours} ساعة`;
                      return `${Math.floor(diffMs / (1000 * 60))} دقيقة`;
                   })()}
                 </span>
               </div>
             </div>
          )}
        </div>
        
        {/* Mobile user info */}
        <div className="p-6 md:hidden border-b border-gray-100">
           <div className="text-sm text-gray-500 font-mono mb-4" dir="ltr" style={{textAlign: 'right'}}>{user.email}</div>
           {subData && (
             <div className="bg-gray-50 rounded-lg p-3 border border-gray-100 space-y-2">
               <div className="flex justify-between items-center">
                 <span className="text-xs text-gray-500">الرصيد:</span>
                 <span className="font-bold font-mono text-primary text-sm">${Number(subData.current_balance || 0).toFixed(2)}</span>
               </div>
               <div className="flex justify-between items-center">
                 <span className="text-xs text-gray-500">الاشتراك:</span>
                 <span className="font-medium text-xs text-gray-700 bg-gray-200 px-2 py-0.5 rounded">
                   {(() => {
                      if (!subData.expires_at) return 'غير محدود';
                      const diffMs = new Date(subData.expires_at).getTime() - Date.now();
                      if (diffMs <= 0) return 'منتهي';
                      const diffDays = Math.floor(diffMs / (1000 * 60 * 60 * 24));
                      if (diffDays >= 30) return `${Math.floor(diffDays / 30)} شهر`;
                      if (diffDays >= 1) return `${diffDays} يوم`;
                      const diffHours = Math.floor(diffMs / (1000 * 60 * 60));
                      if (diffHours >= 1) return `${diffHours} ساعة`;
                      return `${Math.floor(diffMs / (1000 * 60))} دقيقة`;
                   })()}
                 </span>
               </div>
             </div>
          )}
        </div>

        <nav className="flex-1 px-4 py-4 space-y-1 overflow-y-auto">
          {navItems.map((item) => (
            <NavLink
              key={item.name}
              to={item.path}
              onClick={() => setIsMobileMenuOpen(false)}
              className={({ isActive }) =>
                `flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-colors ${
                  isActive 
                    ? 'bg-gray-100 text-primary' 
                    : 'text-gray-600 hover:bg-gray-50 hover:text-primary'
                }`
              }
            >
              <item.icon className="w-5 h-5 flex-shrink-0" />
              {item.name}
            </NavLink>
          ))}
        </nav>
        
        <div className="p-4 border-t border-gray-200">
          <button 
            onClick={handleLogout}
            className="flex items-center gap-3 px-3 py-2 w-full text-gray-600 hover:bg-red-50 hover:text-red-600 rounded-lg text-sm font-medium transition-colors"
          >
            <LogOut className="w-5 h-5 flex-shrink-0" />
            تسجيل الخروج
          </button>
        </div>
      </aside>

      {/* Main Content */}
      <main className="flex-1 overflow-auto bg-gray-50 w-full">
        <div className="p-4 md:p-8 max-w-5xl mx-auto">
          <Outlet />
        </div>
      </main>
    </div>
  );
}
