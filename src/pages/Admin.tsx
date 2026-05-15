import React, { useState, useEffect } from 'react';
import { fetchApi } from '../lib/api';
import toast from 'react-hot-toast';
import { QRCodeSVG } from 'qrcode.react';
import { LayoutDashboard, Users, CreditCard, Settings, LogOut, Menu, X, ArrowDownLeft, ArrowUpRight, Copy, User } from 'lucide-react';

export default function Admin() {
  const [token, setToken] = useState(localStorage.getItem('adminToken') || '');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  
  const [activeTab, setActiveTab] = useState<'dashboard' | 'users' | 'payments' | 'settings'>('dashboard');
  const [stats, setStats] = useState<any>(null);
  const [users, setUsers] = useState<any[]>([]);
  const [deposits, setDeposits] = useState<any[]>([]);
  const [settings, setSettings] = useState<any>({});
  const [adminWalletProfile, setAdminWalletProfile] = useState<any>(null);
  const [adminWalletTransactions, setAdminWalletTransactions] = useState<any[]>([]);
  
  const [linkingWallet, setLinkingWallet] = useState(false);
  const [qrPayload, setQrPayload] = useState<string|null>(null);
  const [pendingWalletId, setPendingWalletId] = useState<string|null>(null);
  const [showAddModal, setShowAddModal] = useState(false);
  const [step, setStep] = useState(1);
  const [isSidebarOpen, setIsSidebarOpen] = useState(false);
  
  // Check if stored token is expired before trying to load data
  const isTokenExpired = (t: string): boolean => {
    try {
      const payload = JSON.parse(atob(t.split('.')[1]));
      if (!payload.exp) return false;
      return Date.now() >= payload.exp * 1000;
    } catch {
      return true;
    }
  };

  useEffect(() => {
    if (token) {
      if (isTokenExpired(token)) {
        localStorage.removeItem('adminToken');
        setToken('');
        toast.error('انتهت صلاحية الجلسة، يرجى تسجيل الدخول مجدداً');
        return;
      }
      loadData();
    }
  }, [token, activeTab]);

  const handleAuthError = (status: number) => {
    if (status === 401 || status === 403) {
      localStorage.removeItem('adminToken');
      setToken('');
      toast.error('انتهت صلاحية الجلسة، يرجى تسجيل الدخول مجدداً');
      return true;
    }
    return false;
  };

  const loadData = async () => {
    try {
      const headers = { 'Authorization': `Bearer ${token}` };
      if (activeTab === 'dashboard') {
         const res = await fetch('/api/admin/stats', { headers });
         if (handleAuthError(res.status)) return;
         if (res.ok) setStats(await res.json());
      } else if (activeTab === 'users') {
         const res = await fetch('/api/admin/users', { headers });
         if (handleAuthError(res.status)) return;
         if (res.ok) {
           const data = await res.json();
           // Backend returns paginated { data: [], total, page, limit }
           setUsers(Array.isArray(data) ? data : (data.data || []));
         }
      } else if (activeTab === 'payments') {
         const res = await fetch('/api/admin/deposits', { headers });
         if (handleAuthError(res.status)) return;
         if (res.ok) {
           const data = await res.json();
           // Backend returns paginated { data: [], total, page, limit }
           setDeposits(Array.isArray(data) ? data : (data.data || []));
         }
      } else if (activeTab === 'settings') {
         const res = await fetch('/api/admin/settings', { headers });
         if (handleAuthError(res.status)) return;
         if (res.ok) {
            const data = await res.json();
            // Handle both array or object from backend just in case
            if (Array.isArray(data)) {
               const obj: any = {};
               data.forEach(item => obj[item.key] = item.value);
               setSettings(obj);
            } else {
               setSettings(data);
            }
         }
         
         const profileRes = await fetch('/api/admin/deposit-wallet/profile', { headers });
         if (profileRes.ok) setAdminWalletProfile(await profileRes.json());
         
         const txRes = await fetch('/api/admin/deposit-wallet/transactions', { headers });
         if (txRes.ok) {
            const txData = await txRes.json();
            setAdminWalletTransactions(txData?.log || []);
         }
      }
    } catch (e) {
      toast.error('حدث خطأ أثناء جلب البيانات');
    }
  };

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    const res = await fetch('/api/admin/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password })
    });
    const data = await res.json();
    if (res.ok) {
      localStorage.setItem('adminToken', data.token);
      setToken(data.token);
      toast.success('تم تسجيل الدخول');
    } else {
      toast.error(data.error);
    }
  };

  const initWalletLink = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    setLinkingWallet(true);
    setQrPayload(null);
    try {
      const res = await fetch('/api/admin/deposit-wallet/init', {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${token}` }
      });
      const data = await res.json();
      if(res.ok) {
         setQrPayload(data.qrPayload);
         setPendingWalletId(data.walletId);
         setStep(2);
      } else {
         toast.error(data.error);
         setLinkingWallet(false);
      }
    } catch(e) {
       setLinkingWallet(false);
    }
  };

  useEffect(() => {
     let int: any;
     if(linkingWallet && pendingWalletId && step === 2) {
        int = setInterval(async () => {
           try {
             const res = await fetch(`/api/admin/deposit-wallet/status/${pendingWalletId}`, {
                headers: { 'Authorization': `Bearer ${token}` }
             });
             const data = await res.json();
             if (data.linked) {
                toast.success('تم ربط المحفظة بنجاح!');
                setLinkingWallet(false);
                setQrPayload(null);
                setPendingWalletId(null);
                setShowAddModal(false);
                setStep(1);
                clearInterval(int);
                loadData();
             }
           } catch(e){}
        }, 3000);
     }
     return () => clearInterval(int);
  }, [linkingWallet, pendingWalletId, step]);

  const updateSetting = async (key: string, value: string) => {
     try {
       const res = await fetch('/api/admin/settings', {
         method: 'POST',
         headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
         body: JSON.stringify({ key, value })
       });
       if(res.ok) {
         toast.success('تم تحديث الإعداد');
         loadData();
       } else {
         toast.error('فشل في التحديث');
       }
     } catch(e) {}
  };

  const reverifyDeposit = async (id: string) => {
      try {
        const res = await fetch(`/api/admin/deposits/${id}/reverify`, {
          method: 'POST',
          headers: { 'Authorization': `Bearer ${token}` }
        });
        const data = await res.json();
        if(res.ok) {
           toast.success('تم إعادة التحقق بنجاح ' + (data.status === 'approved' ? 'وتم الموافقة' : 'وما زال قيد الانتظار'));
           loadData();
        } else {
           toast.error(data.error);
        }
      } catch(e){}
  };

  const handleDepositAction = async (id: string, action: 'approve'|'reject', amount?: number) => {
     try {
        const body: any = {};
        if (action === 'approve') {
           const p = prompt('أدخل المبلغ بالدولار ($):', String(amount || 0));
           if(p === null) return;
           body.amount_usd = Number(p);
        }
        
        const res = await fetch(`/api/admin/deposits/${id}/${action}`, {
           method: 'POST',
           headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
           body: JSON.stringify(body)
        });
        if(res.ok) {
           toast.success('تم الإجراء بنجاح');
           loadData();
        } else {
           toast.error('فشل الإجراء');
        }
     } catch(e){}
  };

  if (!token) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-50 p-4">
        <form onSubmit={handleLogin} className="w-full max-w-sm bg-white p-8 rounded-2xl shadow-sm border border-gray-200" dir="rtl">
           <div className="flex justify-center mb-6">
              <div className="w-16 h-16 bg-red-50 text-red-600 rounded-full flex items-center justify-center border-4 border-red-100">
                 <LayoutDashboard size={28} />
              </div>
           </div>
           <h2 className="text-2xl font-bold mb-6 text-center text-[#0936AD]">لوحة الإدارة العليا</h2>
           <input type="email" placeholder="البريد الإلكتروني" className="w-full p-3 border border-gray-300 rounded-lg mb-4 text-left focus:outline-none focus:ring-2 focus:ring-red-500/20 focus:border-red-500 outline-none transition" dir="ltr" onChange={e => setEmail(e.target.value)} />
           <input type="password" placeholder="كلمة المرور" className="w-full p-3 border border-gray-300 rounded-lg mb-6 text-left focus:outline-none focus:ring-2 focus:ring-red-500/20 focus:border-red-500 outline-none transition" dir="ltr" onChange={e => setPassword(e.target.value)} />
           <button className="w-full bg-primary hover:bg-primary-dark text-white p-3 rounded-lg font-medium transition shadow-sm">تسجيل الدخول</button>
        </form>
      </div>
    );
  }

  const NavItem = ({ id, label, icon: Icon }: { id: string, label: string, icon: any }) => (
    <button 
      onClick={() => { setActiveTab(id as any); setIsSidebarOpen(false); }} 
      className={`p-3 text-right rounded-lg font-medium transition flex items-center gap-3 w-full ${activeTab === id ? 'bg-red-50 text-red-700' : 'hover:bg-gray-50 text-gray-700'}`}
    >
      <Icon size={20} className={activeTab === id ? 'text-red-600' : 'text-gray-400'} />
      <span>{label}</span>
    </button>
  );

  return (
    <div className="min-h-screen bg-gray-50 flex rtl" dir="rtl">
        {/* Mobile Header */}
        <div className="md:hidden fixed top-0 w-full bg-white border-b border-gray-200 p-4 flex justify-between items-center z-20">
          <h2 className="text-xl font-bold tracking-tight text-red-600">SYB Admin</h2>
          <button onClick={() => setIsSidebarOpen(!isSidebarOpen)} className="p-2 text-gray-600">
             {isSidebarOpen ? <X size={24} /> : <Menu size={24} />}
          </button>
        </div>

        {/* Sidebar */}
        <div className={`fixed md:sticky top-0 w-64 bg-white border-l border-gray-200 p-4 flex flex-col gap-2 shadow-sm min-h-screen shrink-0 z-10 transition-transform duration-300 ${isSidebarOpen ? 'translate-x-0' : 'translate-x-full md:translate-x-0'}`}>
            <div className="hidden md:flex items-center gap-2 mb-8 mt-2 px-2">
               <div className="w-8 h-8 bg-red-600 rounded flex items-center justify-center text-white font-bold tracking-widest text-sm">SYB</div>
               <h2 className="text-xl font-bold tracking-tight text-[#0936AD]">Admin</h2>
            </div>
            
            <div className="md:hidden mb-8 mt-16 px-2">
               <h2 className="text-xl font-bold text-[#0936AD]">القائمة</h2>
            </div>
            
            <NavItem id="dashboard" label="الإحصائيات" icon={LayoutDashboard} />
            <NavItem id="users" label="المستخدمين" icon={Users} />
            <NavItem id="payments" label="الإيداعات" icon={CreditCard} />
            <NavItem id="settings" label="الإعدادات" icon={Settings} />
            
            <div className="mt-auto"></div>
            <button 
               onClick={() => { localStorage.removeItem('adminToken'); setToken(''); }} 
               className="p-3 text-right rounded-lg text-red-500 hover:bg-red-50 hover:text-red-700 font-medium w-full flex items-center gap-3 transition"
            >
               <LogOut size={20} />
               <span>تسجيل خروج</span>
            </button>
        </div>

        {/* Main Content */}
        <div className="flex-1 p-6 md:p-10 pt-20 md:pt-10 overflow-x-hidden min-h-screen">
            {activeTab === 'dashboard' && stats && (
               <div className="space-y-6 max-w-5xl">
                  <div className="flex items-center gap-3 mb-6">
                     <div className="bg-red-100 p-2 text-red-600 rounded-lg"><LayoutDashboard size={24} /></div>
                     <h1 className="text-2xl font-bold text-[#0936AD]">نظرة عامة</h1>
                  </div>
                  <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-4">
                     <div className="bg-white p-6 rounded-xl border border-gray-200 shadow-sm flex flex-col justify-between h-32"><p className="text-gray-500 font-medium text-sm">المستخدمين</p><p className="text-3xl font-bold text-[#0936AD]">{stats.users}</p></div>
                     <div className="bg-white p-6 rounded-xl border border-gray-200 shadow-sm flex flex-col justify-between h-32"><p className="text-gray-500 font-medium text-sm">إجمالي الأرصدة</p><p className="text-3xl font-bold text-green-600 font-mono">${stats.total_balance?.toFixed(2)}</p></div>
                     <div className="bg-white p-6 rounded-xl border border-gray-200 shadow-sm flex flex-col justify-between h-32"><p className="text-gray-500 font-medium text-sm">إيداعات معلقة</p><p className="text-3xl font-bold text-orange-600">{stats.pending_deposits}</p></div>
                     <div className="bg-white p-6 rounded-xl border border-gray-200 shadow-sm flex flex-col justify-between h-32"><p className="text-gray-500 font-medium text-sm">محافظ نشطة</p><p className="text-3xl font-bold text-[#0936AD]">{stats.active_wallets}</p></div>
                  </div>
               </div>
            )}

            {activeTab === 'users' && (
               <div className="space-y-6 max-w-6xl">
                  <div className="flex items-center gap-3 mb-6">
                     <div className="bg-red-100 p-2 text-red-600 rounded-lg"><Users size={24} /></div>
                     <h1 className="text-2xl font-bold text-[#0936AD]">إدارة المستخدمين</h1>
                  </div>
                  <div className="bg-white rounded-xl border border-gray-200 shadow-sm overflow-x-auto">
                     <table className="w-full text-right text-sm">
                        <thead className="bg-gray-50 border-b border-gray-100">
                           <tr>
                              <th className="p-4 font-semibold text-gray-700">الاسم / البريد</th>
                              <th className="p-4 font-semibold text-gray-700">الرصيد</th>
                              <th className="p-4 font-semibold text-gray-700">التسجيل</th>
                              <th className="p-4 font-semibold text-gray-700">إجراءات</th>
                           </tr>
                        </thead>
                        <tbody className="divide-y divide-gray-100">
                           {users.map(u => (
                              <tr key={u.id} className="hover:bg-gray-50 transition-colors">
                                 <td className="p-4">
                                     <div className="font-bold text-[#0936AD]">{u.name}</div>
                                     <div className="text-gray-500 text-xs font-mono mt-1" dir="ltr">{u.email}</div>
                                 </td>
                                 <td className="p-4 font-mono font-bold text-green-600">${u.current_balance || 0}</td>
                                 <td className="p-4 text-gray-500">{new Date(u.created_at).toLocaleDateString()}</td>
                                 <td className="p-4">
                                    <button 
                                       className="px-3 py-1.5 bg-white border border-gray-300 text-gray-700 rounded-lg hover:bg-gray-50 font-medium shadow-sm transition"
                                       onClick={async () => {
                                          const val = prompt('أدخل المبلغ المضاف (إضافة إلى الرصيد الحالي):');
                                          if(!val || isNaN(Number(val))) return;
                                          try {
                                             const res = await fetch(`/api/admin/users/${u.id}/add-balance`, {
                                                method: 'POST',
                                                headers: {'Content-Type': 'application/json', 'Authorization': `Bearer ${token}`},
                                                body: JSON.stringify({ amount: Number(val) })
                                             });
                                             if(res.ok) { toast.success('تمت الإضافة'); loadData(); }
                                             else toast.error('خطأ');
                                          } catch(e){}
                                       }}
                                    >
                                       إضافة رصيد
                                    </button>
                                 </td>
                              </tr>
                           ))}
                        </tbody>
                     </table>
                  </div>
               </div>
            )}

            {activeTab === 'payments' && (
               <div className="space-y-6 max-w-5xl">
                   <div className="flex items-center gap-3 mb-6">
                      <div className="bg-red-100 p-2 text-red-600 rounded-lg"><CreditCard size={24} /></div>
                      <h1 className="text-2xl font-bold text-[#0936AD]">الإيداعات</h1>
                   </div>
                   
                   <h2 className="text-lg font-bold text-[#0936AD] border-b pb-2 mb-4">الطلبات المعلقة</h2>
                   <div className="grid gap-4">
                      {deposits.filter(d => ['pending', 'pending_verification'].includes(d.status)).map(d => (
                         <div key={d.id} className="bg-white p-5 rounded-xl border border-orange-200 shadow-sm flex flex-col md:flex-row md:items-center justify-between gap-4">
                            <div>
                               <div className="font-bold text-[#0936AD]">{d.users?.name} <span dir="ltr" className="text-gray-500 font-mono text-sm ml-2 font-normal">{d.users?.email}</span></div>
                               <div className="font-mono mt-2 text-sm bg-gray-100 p-1.5 px-3 rounded inline-block text-gray-700 border border-gray-200" dir="ltr">TX: {d.tx_id}</div>
                               <div className="text-xs text-orange-600 font-medium mt-2">
                                  {d.status === 'pending_verification' ? 'معالجة آلية (انتظار المعاملة)' : 'مراجعة يدوية'}
                               </div>
                            </div>
                            <div className="flex gap-2 flex-wrap">
                               {d.status === 'pending_verification' && <button onClick={() => reverifyDeposit(d.id)} className="px-4 py-2 bg-blue-50 text-blue-600 border border-blue-100 rounded-lg font-medium hover:bg-blue-100 transition shadow-sm">إعادة تحقق</button>}
                               <button onClick={() => handleDepositAction(d.id, 'approve', d.amount_usd)} className="px-4 py-2 bg-green-50 text-green-700 border border-green-100 rounded-lg font-medium hover:bg-green-100 transition shadow-sm">موافقة يدوية</button>
                               <button onClick={() => handleDepositAction(d.id, 'reject')} className="px-4 py-2 text-red-600 bg-white border border-red-200 rounded-lg hover:bg-red-50 font-medium transition shadow-sm flex-1 md:flex-none">رفض</button>
                            </div>
                         </div>
                      ))}
                      {deposits.filter(d => ['pending', 'pending_verification'].includes(d.status)).length === 0 && (
                         <div className="bg-gray-50 border border-gray-200 border-dashed rounded-xl p-8 text-center text-gray-500">لا توجد طلبات معلقة بانتظار المراجعة</div>
                      )}
                   </div>

                   <h2 className="text-lg font-bold text-[#0936AD] border-b pb-2 mb-4 mt-10">المكتملة والمرفوضة</h2>
                   <div className="bg-white rounded-xl border border-gray-200 shadow-sm overflow-x-auto text-sm">
                      <table className="w-full text-right min-w-[600px]">
                         <thead className="bg-gray-50 border-b border-gray-100">
                            <tr>
                               <th className="p-4 font-semibold text-gray-700">المستخدم</th>
                               <th className="p-4 font-semibold text-gray-700">رقم العملية</th>
                               <th className="p-4 font-semibold text-gray-700">المبلغ</th>
                               <th className="p-4 font-semibold text-gray-700">التحقق</th>
                               <th className="p-4 font-semibold text-gray-700">الحالة</th>
                            </tr>
                         </thead>
                         <tbody className="divide-y divide-gray-100">
                            {deposits.filter(d => !['pending', 'pending_verification'].includes(d.status)).map(d => (
                               <tr key={d.id} className="hover:bg-gray-50">
                                  <td className="p-4 truncate" dir="ltr">{d.users?.email}</td>
                                  <td className="p-4 font-mono text-gray-600 bg-gray-50 rounded mx-4 inline-block mt-2 border border-gray-100">{d.tx_id}</td>
                                  <td className="p-4 font-mono font-bold text-[#0936AD]">${d.amount_usd}</td>
                                  <td className="p-4">{d.verification_method === 'auto' ? <span className="bg-blue-50 text-blue-700 px-2 py-0.5 rounded text-xs">تلقائي</span> : <span className="bg-gray-100 text-gray-700 px-2 py-0.5 rounded text-xs">يدوي</span>}</td>
                                  <td className="p-4">
                                     {d.status === 'approved' ? <span className="text-green-600 bg-green-50 px-2 py-1 rounded text-xs font-semibold">اكتمل</span> : <span className="text-red-600 bg-red-50 px-2 py-1 rounded text-xs font-semibold">مرفوض</span>}
                                  </td>
                               </tr>
                            ))}
                         </tbody>
                      </table>
                   </div>
               </div>
            )}

            {activeTab === 'settings' && (
               <div className="space-y-6 max-w-2xl">
                  <div className="flex items-center gap-3 mb-6">
                     <div className="bg-red-100 p-2 text-red-600 rounded-lg"><Settings size={24} /></div>
                     <h1 className="text-2xl font-bold text-[#0936AD]">إعدادات النظام</h1>
                  </div>
                  
                  <div className="bg-white p-6 rounded-xl border border-gray-200 shadow-sm">
                     <h3 className="font-bold text-lg mb-4 text-[#0936AD] border-b pb-2">إعدادات الإيداع</h3>
                     <div className="mb-6">
                        <label className="block text-sm font-medium mb-2 text-gray-700">سعر الصرف (1 دولار = ؟ ليرة سورية)</label>
                        <div className="flex gap-2">
                           <input 
                              type="number" 
                              className="w-full border border-gray-300 rounded-lg px-4 py-2 focus:outline-none focus:ring-1 focus:ring-primary font-mono"
                              value={settings.syp_to_usd_rate || ''}
                              onChange={(e) => {
                                 setSettings({ ...settings, syp_to_usd_rate: e.target.value });
                              }}
                              placeholder="14500"
                           />
                           <button onClick={(e) => {
                               updateSetting('syp_to_usd_rate', settings.syp_to_usd_rate);
                           }} className="px-6 py-2 bg-primary hover:bg-primary-dark text-white rounded-lg font-medium transition shadow-sm whitespace-nowrap">حفظ</button>
                        </div>
                     </div>
                     
                     <div className="mt-8">
                        <h4 className="font-bold mb-3 text-[#0936AD]">محفظة استلام الإيداعات (شام كاش)</h4>
                        
                        <div className="mb-6">
                           <label className="block text-sm font-medium mb-2 text-gray-700">رقم محفظة الإيداع للمستخدمين</label>
                           <div className="flex gap-2">
                              <input 
                                 type="text" 
                                 className="w-full border border-gray-300 rounded-lg px-4 py-2 focus:outline-none focus:ring-1 focus:ring-primary font-mono text-left"
                                 value={settings.deposit_wallet_address || ''}
                                 onChange={(e) => {
                                    setSettings({ ...settings, deposit_wallet_address: e.target.value });
                                 }}
                                 placeholder="ex: 09..."
                                 dir="ltr"
                              />
                              <button onClick={(e) => {
                                  updateSetting('deposit_wallet_address', settings.deposit_wallet_address);
                              }} className="px-6 py-2 bg-primary hover:bg-primary-dark text-white rounded-lg font-medium transition shadow-sm whitespace-nowrap">حفظ</button>
                           </div>
                        </div>

                        {adminWalletProfile ? (
                           <div className="mb-4 p-4 bg-green-50 text-green-700 rounded-lg border border-green-200 font-mono break-all text-sm flex items-center justify-between" dir="ltr">
                              <span>يعمل نظام التحقق الآلي على محفظة مرتبطة</span>
                           </div>
                        ) : (
                           <div className="mb-4 p-4 bg-red-50 text-red-600 rounded-lg border border-red-200 text-sm flex items-center gap-2">
                              <div className="w-2 h-2 rounded-full bg-red-500 animate-pulse"></div>
                              لم يتم ربط أي محفظة للتحقق الآلي بعد. يرجى الربط بالأسفل.
                           </div>
                        )}
                        
                        {!linkingWallet && !qrPayload && (
                           <button onClick={() => { setShowAddModal(true); setStep(1); }} className="w-full p-3 bg-white border border-gray-300 hover:bg-gray-50 text-[#0936AD] rounded-lg font-medium shadow-sm transition">إعادة ربط / ربط محفظة جديدة</button>
                        )}
                        
                        {adminWalletProfile && !linkingWallet && !qrPayload && (
                           <div className="mt-8 border-t border-gray-100 pt-8">
                              <h4 className="flex items-center gap-2 font-bold text-lg mb-4 pb-4 border-b border-gray-100">
                                 <User className="w-5 h-5" />
                                 معلومات الحساب
                              </h4>
                              
                              <div className="space-y-3 text-sm mb-8 bg-gray-50 p-4 rounded-xl border border-gray-100">
                                 <div className="flex justify-between items-center"><span className="text-gray-500 min-w-[50px]">الاسم:</span> <span className="font-medium text-left break-words">{adminWalletProfile.name || adminWalletProfile.clientName}</span></div>
                                 <div className="flex justify-between items-center"><span className="text-gray-500 min-w-[50px]">الهاتف:</span> <span className="font-medium text-left" dir="ltr">{adminWalletProfile.phone || adminWalletProfile.accountNumber}</span></div>
                                 <div className="flex justify-between items-center"><span className="text-gray-500 shrink-0">الحساب:</span> <span className="font-medium font-mono break-all text-left max-w-[60%]">{adminWalletProfile.accountNumber}</span></div>
                                 <div className="flex justify-between items-center"><span className="text-gray-500 shrink-0">العنوان:</span> <span className="font-medium font-mono break-all text-left max-w-[60%]">{adminWalletProfile.address || adminWalletProfile.walletAddress || 'غير متوفر'}</span></div>
                              </div>
                              
                              <h4 className="font-bold text-lg mb-4">الأرصدة الحالية</h4>
                              <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-8 text-center">
                                 {['usd', 'syp', 'eur'].map(currency => {
                                      const label = currency === 'syp' ? 'ليرة سورية' : currency === 'usd' ? 'دولار أمريكي' : 'يورو';
                                      const symbol = currency === 'syp' ? 'ل.س' : currency === 'usd' ? '$' : '€';
                                      
                                      // Note: in early implementation the api might return total balance for SYP by default,
                                      // and currency-specific balances. Let's try to extract if array is available.
                                      // Using adminWalletProfile.balances array if present.
                                      let amount = 0;
                                      if (adminWalletProfile.balances && Array.isArray(adminWalletProfile.balances)) {
                                          const b = adminWalletProfile.balances.find((x: any) => 
                                             x.currencyId === currency.toUpperCase() || 
                                             x.currency === currency.toUpperCase() || 
                                             x.currencyId === (currency === 'syp' ? 2 : currency === 'usd' ? 1 : 3)
                                          );
                                          if (b) amount = b.balance || b.amount || 0;
                                      } else if (currency === 'syp') {
                                          amount = adminWalletProfile.balance || 0;
                                      }

                                      return (
                                        <div key={currency} className="p-4 bg-gray-50 rounded-xl border border-gray-100 flex flex-col items-center justify-center">
                                           <span className="text-gray-500 font-medium text-sm mb-2">{label}</span>
                                           <span className="text-xl font-bold font-mono" dir="ltr">{symbol}{currency === 'syp' ? Number(amount).toLocaleString() : Number(amount).toFixed(2)}</span>
                                        </div>
                                      );
                                 })}
                              </div>
                              
                              <h4 className="font-bold mb-4 text-[#0936AD] border-b pb-2 text-lg">سجل الحركات</h4>
                              <div className="overflow-x-auto text-sm w-full bg-white border border-gray-200 rounded-xl">
                                 <table className="w-full text-right min-w-[700px]">
                                   <thead className="bg-gray-50 text-gray-500 border-b border-gray-200">
                                     <tr>
                                       <th className="px-5 py-3 font-medium">النوع</th>
                                       <th className="px-5 py-3 font-medium">المبلغ</th>
                                       <th className="px-5 py-3 font-medium">الطرف الآخر</th>
                                       <th className="px-5 py-3 font-medium">التاريخ</th>
                                       <th className="px-5 py-3 font-medium">رقم العملية</th>
                                     </tr>
                                   </thead>
                                   <tbody className="divide-y divide-gray-100">
                                   {adminWalletTransactions && adminWalletTransactions.length > 0 ? (
                                       adminWalletTransactions.map((tx: any) => {
                                          const isIncoming = tx.tranKind === 1 || tx.type === 'in' || tx.type === 'income';
                                          return (
                                            <tr key={tx.tranId || tx.id} className="hover:bg-gray-50">
                                               <td className="px-5 py-4 whitespace-nowrap">
                                                 {isIncoming ? (
                                                   <span className="flex items-center gap-1 text-green-600 font-medium">
                                                     <ArrowDownLeft className="w-3.5 h-3.5" /> استلام
                                                   </span>
                                                 ) : (
                                                   <span className="flex items-center gap-1 text-red-600 font-medium">
                                                     <ArrowUpRight className="w-3.5 h-3.5" /> إرسال
                                                   </span>
                                                 )}
                                               </td>
                                               <td className="px-5 py-4 font-mono font-bold whitespace-nowrap" dir="ltr">
                                                 {isIncoming 
                                                   ? <span className="text-green-600">+{tx.amount} {tx.currencyName || tx.currency || 'SYP'}</span> 
                                                   : <span className="text-red-600">-{tx.amount} {tx.currencyName || tx.currency || 'SYP'}</span>}
                                               </td>
                                               <td className="px-5 py-4 text-gray-700">
                                                  <div className="font-medium truncate max-w-[150px]">{tx.peerUserName || tx.peerAccountInfo?.name || tx.peerAccount || 'غير متوفر'}</div>
                                                  <div className="text-xs text-gray-500 font-mono truncate max-w-[150px]">{tx.peerAccountNumber || tx.peerAccountAddress || ''}</div>
                                               </td>
                                               <td className="px-5 py-4 text-gray-500 whitespace-nowrap" dir="ltr">
                                                 {tx.tranDate} {tx.tranTime}
                                               </td>
                                                <td className="px-5 py-4 font-mono text-gray-500 text-xs">
                                                  {tx.tranId || tx.id}
                                                </td>
                                              </tr>
                                           );
                                        })
                                    ) : (
                                       <tr>
                                          <td colSpan={5} className="py-8 text-center text-gray-500">لا توجد عمليات</td>
                                       </tr>
                                    )}
                                    </tbody>
                                  </table>
                                </div>
                             </div>
                          )}
                       </div>
                    </div>
                 </div>
              )}
          </div>
          
          {/* Overlay for mobile sidebar */}
          {isSidebarOpen && (
             <div className="fixed inset-0 bg-primary/20 z-0 md:hidden" onClick={() => setIsSidebarOpen(false)}></div>
          )}
          
          {/* Admin Wallet Link Modal */}
          {showAddModal && (
             <div className="fixed inset-0 bg-primary/50 flex items-center justify-center p-4 z-50">
                <div className="bg-white rounded-2xl w-full max-w-md p-6 relative">
                  <button 
                    onClick={() => { setShowAddModal(false); setPendingWalletId(null); setLinkingWallet(false); setQrPayload(null); setStep(1); }}
                    className="absolute top-4 left-4 text-gray-400 hover:text-gray-600"
                  >
                    ✕
                  </button>
                  <div className="flex items-center gap-3 mb-6">
                    <div className="bg-blue-50 text-blue-600 p-2 rounded-lg">
                      <Settings className="w-6 h-6" />
                    </div>
                    <h2 className="text-xl font-bold">ربط محفظة الآدمن</h2>
                  </div>
                  
                  {step === 1 ? (
                    <form onSubmit={initWalletLink}>
                      <p className="text-sm text-gray-600 mb-6">
                        هل أنت متأكد من رغبتك في تحديث محفظة الإيداع الرسمية؟ سيتم إيقاف معالجة الإيداعات الآلية على المحفظة القديمة بمجرد ربط المحفظة الجديدة.
                      </p>
                      <button 
                        type="submit"
                        className="w-full bg-primary text-white py-3 rounded-lg font-medium hover:bg-primary-dark transition-colors"
                      >
                        التالي: توليد الرمز (QR)
                      </button>
                    </form>
                  ) : (
                    <div>
                      <p className="text-sm text-gray-600 mb-6 text-center">
                        افتح تطبيق شام كاش ثم توجه إلى الحساب ثم الأجهزة المرتبطة ثم مسح code qr لربط الجهاز ووجه الكاميرا إلى المربع أدناه.
                      </p>
                      
                      <div className="bg-white p-6 rounded-xl flex items-center justify-center mb-6 border-2 border-gray-100 shadow-sm mx-auto w-fit">
                        {qrPayload ? (
                           <QRCodeSVG value={qrPayload} size={200} level="H" />
                        ) : (
                           <div className="w-[200px] h-[200px] flex items-center justify-center text-gray-400">لا يوجد بيانات QR</div>
                        )}
                      </div>
     
                      <p className="text-center text-sm text-gray-500 flex items-center justify-center gap-2">
                        <span className="w-4 h-4 border-2 border-gray-300 border-t-primary-dark rounded-full animate-spin"></span>
                        ننتظر تأكيد الربط من التطبيق...
                      </p>
                    </div>
                  )}
                </div>
             </div>
          )}
      </div>
    );
}
