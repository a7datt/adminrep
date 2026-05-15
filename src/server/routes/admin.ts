import express from 'express';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { z } from 'zod';
import { supabase } from '../db.js';
import { ShamCashService } from '../../services/shamy.js';
import { logAuditEvent, adminLoginRateLimiter, reverifyRateLimiter } from '../middleware.js';
import { revokeAllUserTokens } from './auth.js';

const router = express.Router();

const ADMIN_JWT_SECRET = process.env.ADMIN_JWT_SECRET;
if (!ADMIN_JWT_SECRET) throw new Error('ADMIN_JWT_SECRET environment variable is required');

// UUID validation
const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
function isValidUUID(id: string): boolean {
  return uuidRegex.test(id);
}

const loginSchema = z.object({
  email: z.string().email().max(255).toLowerCase().trim(),
  password: z.string().min(1).max(128),
});

const addBalanceSchema = z.object({
  amount: z.number().positive('Amount must be positive').max(100000).finite(),
});

const changePasswordSchema = z.object({
  current_password: z.string().min(1).max(128),
  new_password: z
    .string()
    .min(12, 'Admin password must be at least 12 characters')
    .max(128)
    .regex(/[A-Z]/, 'Must contain uppercase')
    .regex(/[a-z]/, 'Must contain lowercase')
    .regex(/[0-9]/, 'Must contain number')
    .regex(/[^A-Za-z0-9]/, 'Must contain special character'),
});

const directionSchema = z.enum(['all', 'in', 'out']).default('all');

// ─── Admin JWT middleware ─────────────────────
const authenticateAdmin = (req: express.Request, res: express.Response, next: express.NextFunction) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    res.status(401).json({ error: 'Missing token' });
    return;
  }

  jwt.verify(token, ADMIN_JWT_SECRET!, (err, admin) => {
    if (err) {
      res.status(403).json({ error: 'Invalid or expired token' });
      return;
    }
    (req as any).admin = admin;
    next();
  });
};

// ─── Admin Login ──────────────────────────────
router.post('/login', adminLoginRateLimiter, async (req, res) => {
  try {
    const parseResult = loginSchema.safeParse(req.body);
    if (!parseResult.success) {
      res.status(400).json({ error: 'Invalid credentials format' });
      return;
    }
    const { email, password } = parseResult.data;

    const { data: admin, error } = await supabase
      .from('admins')
      .select('id, email, password_hash')
      .eq('email', email)
      .single();

    if (error || !admin) {
      // Constant-time dummy compare to prevent timing attacks
      await bcrypt.compare(password, '$2b$12$invalidhashfortimingnormalization000000000000000000000');
      await logAuditEvent(null, 'ADMIN_LOGIN_FAILED', { email }, req.ip);
      res.status(401).json({ error: 'Invalid credentials' });
      return;
    }

    const valid = await bcrypt.compare(password, admin.password_hash);
    if (!valid) {
      await logAuditEvent(admin.id, 'ADMIN_LOGIN_FAILED', { email }, req.ip);
      res.status(401).json({ error: 'Invalid credentials' });
      return;
    }

    await logAuditEvent(admin.id, 'ADMIN_LOGIN_SUCCESS', { email }, req.ip);

    // SECURITY: Admin tokens are short-lived (1 hour)
    const token = jwt.sign(
      { adminId: admin.id, role: 'admin' },
      ADMIN_JWT_SECRET!,
      { expiresIn: '1h' }
    );

    res.json({ token, admin: { id: admin.id, email: admin.email } });
  } catch (error) {
    console.error('[Admin Login Error]', (error as Error).message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// All routes below require admin authentication
router.use(authenticateAdmin);

// ─── Users — paginated to prevent DoS ────────
router.get('/users', async (req, res) => {
  try {
    // SECURITY: Paginate to prevent loading entire user table in one request
    const page = Math.max(1, Number(req.query.page) || 1);
    const limit = Math.min(100, Math.max(1, Number(req.query.limit) || 50));
    const offset = (page - 1) * limit;

    const { data: users, error: usersErr, count } = await supabase
      .from('users')
      .select('id, name, email, created_at', { count: 'exact' })
      .range(offset, offset + limit - 1)
      .order('created_at', { ascending: false });

    if (usersErr) throw usersErr;

    const userIds = (users || []).map(u => u.id);

    const [subsResult, walletsResult, depositsResult] = await Promise.all([
      supabase
        .from('subscriptions')
        .select('user_id, status, current_balance, expires_at')
        .in('user_id', userIds),
      supabase
        .from('wallets')
        .select('user_id, id')
        .in('user_id', userIds),
      supabase
        .from('deposit_requests')
        .select('user_id, amount_usd')
        .eq('status', 'approved')
        .in('user_id', userIds),
    ]);

    const subs = subsResult.data || [];
    const wallets = walletsResult.data || [];
    const deposits = depositsResult.data || [];

    const result = (users || []).map(u => {
      const uSub = subs.find(s => s.user_id === u.id) || {
        current_balance: 0,
        status: 'inactive',
        expires_at: null,
      };
      const uWallets = wallets.filter(w => w.user_id === u.id);
      const uDeposits = deposits
        .filter(d => d.user_id === u.id)
        .reduce((acc, curr) => acc + Number(curr.amount_usd), 0);
      return {
        ...u,
        current_balance: uSub.current_balance,
        subscription_status: uSub.status,
        expires_at: uSub.expires_at,
        wallets_count: uWallets.length,
        total_deposits: uDeposits,
      };
    });

    res.json({ data: result, total: count || 0, page, limit });
  } catch (error) {
    console.error('[Admin Users Error]', (error as Error).message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ─── Stats ────────────────────────────────────
router.get('/stats', async (req, res) => {
  try {
    const { count: usersCount } = await supabase
      .from('users')
      .select('*', { count: 'exact', head: true });

    const { data: subs } = await supabase
      .from('subscriptions')
      .select('current_balance');
    const totalBalance = subs?.reduce((acc, curr) => acc + Number(curr.current_balance), 0) || 0;

    const { count: pendingCount } = await supabase
      .from('deposit_requests')
      .select('*', { count: 'exact', head: true })
      .in('status', ['pending', 'pending_verification']);

    const { count: walletsCount } = await supabase
      .from('wallets')
      .select('*', { count: 'exact', head: true })
      .eq('status', 'active');

    const { data: recentDeposits } = await supabase
      .from('deposit_requests')
      .select('*, users(name, email)')
      .order('created_at', { ascending: false })
      .limit(5);

    res.json({
      users: usersCount || 0,
      total_balance: totalBalance,
      pending_deposits: pendingCount || 0,
      active_wallets: walletsCount || 0,
      recent_deposits: recentDeposits || [],
    });
  } catch (error) {
    console.error('[Admin Stats Error]', (error as Error).message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ─── Add Balance ──────────────────────────────
router.post('/users/:id/add-balance', async (req, res) => {
  try {
    const parseResult = addBalanceSchema.safeParse(req.body);
    if (!parseResult.success) {
      return res.status(400).json({ error: parseResult.error.errors[0].message });
    }
    const { amount } = parseResult.data;
    const userId = req.params.id;

    if (!isValidUUID(userId)) {
      return res.status(400).json({ error: 'Invalid user ID format' });
    }

    const { data: user } = await supabase.from('users').select('id').eq('id', userId).single();
    if (!user) return res.status(404).json({ error: 'User not found' });

    // SECURITY: Atomic RPC to prevent race condition double-credit
    const { error: balanceErr } = await supabase.rpc('add_user_balance', {
      p_user_id: userId,
      p_amount: amount,
    });

    if (balanceErr) throw balanceErr;

    const { data: sub } = await supabase
      .from('subscriptions')
      .select('current_balance')
      .eq('user_id', userId)
      .single();

    await supabase.from('deposit_requests').insert({
      user_id: userId,
      amount_usd: amount,
      tx_id: `manual-${Date.now()}-${crypto.randomUUID()}`,
      status: 'approved',
      admin_note: 'Added manually by admin',
      reviewed_at: new Date().toISOString(),
    });

    const adminId = (req as any).admin?.adminId;
    await logAuditEvent(adminId, 'ADMIN_ADD_BALANCE', { targetUser: userId, amount }, req.ip);

    res.json({ success: true, new_balance: sub?.current_balance });
  } catch (error) {
    console.error('[Add Balance Error]', (error as Error).message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ─── Deposit Wallet ───────────────────────────
router.post('/deposit-wallet/init', async (req, res) => {
  try {
    const { data: activeSetting } = await supabase
      .from('system_settings')
      .select('value')
      .eq('key', 'deposit_wallet_id')
      .maybeSingle();

    if (activeSetting?.value) {
      const { data: existingWallet } = await supabase
        .from('admin_wallets')
        .select('id, status')
        .eq('id', activeSetting.value)
        .maybeSingle();

      if (existingWallet && existingWallet.status === 'active') {
        return res.status(400).json({
          error: 'An active deposit wallet already exists. Unlink the current wallet first.',
        });
      }
    }

    const { data: adminWallet, error } = await supabase
      .from('admin_wallets')
      .insert({ status: 'pending', name: 'Deposit Wallet' })
      .select('id')
      .single();

    if (error) throw error;

    const { data: existing } = await supabase
      .from('system_settings')
      .select('key')
      .eq('key', 'deposit_wallet_id')
      .maybeSingle();

    if (existing) {
      await supabase
        .from('system_settings')
        .update({ value: adminWallet.id })
        .eq('key', 'deposit_wallet_id');
    } else {
      await supabase
        .from('system_settings')
        .insert({ key: 'deposit_wallet_id', value: adminWallet.id });
    }

    const qrPayload = await ShamCashService.initiateWalletLink(adminWallet.id, 'system', 'admin_wallets');

    const adminId = (req as any).admin?.adminId;
    await logAuditEvent(adminId, 'ADMIN_INIT_DEPOSIT_WALLET', { walletId: adminWallet.id }, req.ip);

    res.json({ walletId: adminWallet.id, qrPayload });
  } catch (error) {
    console.error('[Deposit Wallet Init Error]', (error as Error).message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.get('/deposit-wallet/status/:walletId', async (req, res) => {
  try {
    const { walletId } = req.params;
    if (!walletId) return res.json({ linked: false });

    if (!isValidUUID(walletId)) {
      return res.status(400).json({ error: 'Invalid wallet ID format' });
    }

    const { data: wallet, error } = await supabase
      .from('admin_wallets')
      .select('status, wallet_address')
      .eq('id', walletId)
      .maybeSingle();

    if (error) console.error('Error fetching admin_wallets in status:', error.message);

    if (wallet && wallet.status === 'active') {
      res.json({ linked: true, address: wallet.wallet_address });
    } else {
      res.json({ linked: false });
    }
  } catch (error) {
    console.error('[Deposit Wallet Status Error]', (error as Error).message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.get('/deposit-wallet/profile', async (req, res) => {
  try {
    const client = await ShamCashService.getClientForAdminWallet();
    const profile = await client.account.getMyProfile();
    let balances = [];
    try {
      const balRes = await client.account.getBalances();
      balances = balRes.balances || balRes || [];
    } catch (e) {
      console.error('Error fetching admin wallet balances:', (e as Error).message);
    }
    res.json({ ...profile, balances });
  } catch (error) {
    console.error('[Deposit Wallet Profile Error]', (error as Error).message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.get('/deposit-wallet/transactions', async (req, res) => {
  try {
    const { page = '1', limit = '20' } = req.query;

    const directionParsed = directionSchema.safeParse(req.query.direction ?? 'all');
    const direction = directionParsed.success ? directionParsed.data : 'all';

    const safePage = Math.max(1, Number(page));
    const safeLimit = Math.min(100, Math.max(1, Number(limit)));

    const client = await ShamCashService.getClientForAdminWallet();
    const tx = await client.history.getLogs(safePage, safeLimit, { direction });
    res.json(tx);
  } catch (error) {
    if (
      (error as Error).message?.includes('محفظة الإيداع غير نشطة') ||
      (error as Error).message?.includes('لم يتم ربط')
    ) {
      return res.json({ log: [], msg: 'Wallet not linked' });
    }
    console.error('[Deposit Wallet Transactions Error]', (error as Error).message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ─── System Settings ──────────────────────────
router.get('/settings', async (req, res) => {
  try {
    const { data } = await supabase.from('system_settings').select('*');
    const settings =
      data?.reduce((acc: any, curr) => {
        acc[curr.key] = curr.value;
        return acc;
      }, {}) || {};
    res.json(settings);
  } catch (error) {
    console.error('[Settings Get Error]', (error as Error).message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.post('/settings', async (req, res) => {
  try {
    const settingSchema = z.object({
      key: z.string().min(1).max(100).regex(/^[a-z_]+$/),
      value: z.string().max(1000),
    });

    const parseResult = settingSchema.safeParse(req.body);
    if (!parseResult.success) {
      return res.status(400).json({ error: parseResult.error.errors[0].message });
    }
    const { key, value } = parseResult.data;

    const { data: existing } = await supabase
      .from('system_settings')
      .select('key')
      .eq('key', key)
      .maybeSingle();

    if (existing) {
      const { error } = await supabase
        .from('system_settings')
        .update({ value, updated_at: new Date().toISOString() })
        .eq('key', key);
      if (error) throw error;
    } else {
      const { error } = await supabase
        .from('system_settings')
        .insert({ key, value, updated_at: new Date().toISOString() });
      if (error) throw error;
    }

    const adminId = (req as any).admin?.adminId;
    await logAuditEvent(adminId, 'ADMIN_UPDATE_SETTING', { key }, req.ip);

    res.json({ success: true });
  } catch (error) {
    console.error('[Settings Post Error]', (error as Error).message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ─── Deposits — paginated ─────────────────────
router.get('/deposits', async (req, res) => {
  try {
    // SECURITY: Paginate to prevent loading entire deposits table
    const page = Math.max(1, Number(req.query.page) || 1);
    const limit = Math.min(100, Math.max(1, Number(req.query.limit) || 50));
    const offset = (page - 1) * limit;

    const { data, error, count } = await supabase
      .from('deposit_requests')
      .select('*, users(name, email)', { count: 'exact' })
      .order('created_at', { ascending: false })
      .range(offset, offset + limit - 1);

    if (error) throw error;
    res.json({ data: data || [], total: count || 0, page, limit });
  } catch (error) {
    console.error('[Admin Deposits Error]', (error as Error).message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.post('/deposits/:id/approve', async (req, res) => {
  try {
    const approveSchema = z.object({
      amount_usd: z.number().positive().max(100000).finite(),
    });
    const parseResult = approveSchema.safeParse(req.body);
    if (!parseResult.success) {
      return res.status(400).json({ error: parseResult.error.errors[0].message });
    }
    const { amount_usd } = parseResult.data;
    const depId = req.params.id;

    if (!isValidUUID(depId)) {
      return res.status(400).json({ error: 'Invalid deposit ID format' });
    }

    const { data: reqData, error: reqErr } = await supabase
      .from('deposit_requests')
      .select('user_id, status')
      .eq('id', depId)
      .single();

    if (reqErr || !reqData || reqData.status !== 'pending') {
      return res.status(400).json({ error: 'Request not found or not pending' });
    }

    // SECURITY: Atomic status update to prevent race conditions
    const { data: updated, error: updErr } = await supabase
      .from('deposit_requests')
      .update({ status: 'approved', amount_usd, reviewed_at: new Date().toISOString() })
      .eq('id', depId)
      .eq('status', 'pending')
      .select('id');

    if (updErr) throw updErr;

    if (!updated || updated.length === 0) {
      return res.status(409).json({ error: 'Deposit already processed.' });
    }

    const { error: balanceErr } = await supabase.rpc('add_user_balance', {
      p_user_id: reqData.user_id,
      p_amount: amount_usd,
    });

    if (balanceErr) throw balanceErr;

    const adminId = (req as any).admin?.adminId;
    await logAuditEvent(adminId, 'ADMIN_APPROVE_DEPOSIT', {
      depositId: depId,
      amount_usd,
      userId: reqData.user_id,
    }, req.ip);

    res.json({ success: true });
  } catch (error) {
    console.error('[Admin Approve Deposit Error]', (error as Error).message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.post('/deposits/:id/reject', async (req, res) => {
  try {
    const rejectSchema = z.object({
      admin_note: z.string().max(500).optional(),
    });
    const parseResult = rejectSchema.safeParse(req.body);
    if (!parseResult.success) {
      return res.status(400).json({ error: parseResult.error.errors[0].message });
    }
    const { admin_note } = parseResult.data;
    const depId = req.params.id;

    if (!isValidUUID(depId)) {
      return res.status(400).json({ error: 'Invalid deposit ID format' });
    }

    const { data: reqData, error: fetchErr } = await supabase
      .from('deposit_requests')
      .select('status')
      .eq('id', depId)
      .single();

    if (fetchErr || !reqData) {
      return res.status(404).json({ error: 'Deposit request not found' });
    }

    if (!['pending', 'pending_verification'].includes(reqData.status)) {
      return res.status(400).json({ error: 'Cannot reject a deposit that is not pending.' });
    }

    const { error } = await supabase
      .from('deposit_requests')
      .update({ status: 'rejected', admin_note, reviewed_at: new Date().toISOString() })
      .eq('id', depId);

    if (error) throw error;

    const adminId = (req as any).admin?.adminId;
    await logAuditEvent(adminId, 'ADMIN_REJECT_DEPOSIT', { depositId: depId }, req.ip);

    res.json({ success: true });
  } catch (error) {
    console.error('[Admin Reject Deposit Error]', (error as Error).message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// SECURITY: Rate-limited to prevent flooding admin reverify endpoint
router.post('/deposits/:id/reverify', reverifyRateLimiter, async (req, res) => {
  try {
    const depId = req.params.id;

    if (!isValidUUID(depId)) {
      return res.status(400).json({ error: 'Invalid deposit ID format' });
    }

    const { data: reqData, error: reqErr } = await supabase
      .from('deposit_requests')
      .select('user_id, status, tx_id')
      .eq('id', depId)
      .single();

    if (
      reqErr ||
      !reqData ||
      !['pending', 'pending_verification'].includes(reqData.status)
    ) {
      return res.status(400).json({ error: 'Request not found or cannot be verified' });
    }

    let verification;
    try {
      verification = await ShamCashService.verifyDepositTransaction(reqData.tx_id);
    } catch (e: any) {
      if (
        e.message?.includes('لم يتم ربط محفظة الإيداع بعد') ||
        e.message?.includes('محفظة الإيداع غير نشطة')
      ) {
        return res.status(400).json({
          error: 'Deposit wallet not linked yet. Please link it first.',
        });
      }
      throw e;
    }

    if (verification.found && verification.amount_usd) {
      const { data: existing } = await supabase
        .from('deposit_requests')
        .select('id')
        .eq('tx_id', reqData.tx_id)
        .eq('status', 'approved')
        .single();

      if (existing) {
        return res.status(400).json({ error: 'This transaction has already been credited.' });
      }

      // SECURITY: Atomic status update
      const { data: updated, error: updErr } = await supabase
        .from('deposit_requests')
        .update({
          status: 'approved',
          amount_usd: verification.amount_usd,
          reviewed_at: new Date().toISOString(),
        })
        .eq('id', depId)
        .in('status', ['pending', 'pending_verification'])
        .select('id');

      if (updErr) throw updErr;

      if (!updated || updated.length === 0) {
        return res.status(409).json({ error: 'This request was already processed.' });
      }

      const { error: balanceErr } = await supabase.rpc('add_user_balance', {
        p_user_id: reqData.user_id,
        p_amount: verification.amount_usd,
      });

      if (balanceErr) throw balanceErr;

      const adminId = (req as any).admin?.adminId;
      await logAuditEvent(adminId, 'ADMIN_REVERIFY_DEPOSIT', {
        depositId: depId,
        amount: verification.amount_usd,
      }, req.ip);

      return res.json({ success: true, message: `Transaction verified! $${verification.amount_usd} added.` });
    } else {
      await supabase
        .from('deposit_requests')
        .update({ status: 'pending_verification' })
        .eq('id', depId);
      return res.status(400).json({ error: 'Transaction not found or invalid' });
    }
  } catch (error) {
    console.error('[Admin Reverify Error]', (error as Error).message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ─── Change Admin Password ────────────────────
router.post('/change-password', async (req, res) => {
  try {
    const parseResult = changePasswordSchema.safeParse(req.body);
    if (!parseResult.success) {
      return res.status(400).json({ error: parseResult.error.errors[0].message });
    }
    const { current_password, new_password } = parseResult.data;
    const adminId = (req as any).admin.adminId;

    const { data: admin } = await supabase
      .from('admins')
      .select('password_hash')
      .eq('id', adminId)
      .single();

    if (!admin) return res.status(404).json({ error: 'Admin not found' });

    const valid = await bcrypt.compare(current_password, admin.password_hash);
    if (!valid) return res.status(400).json({ error: 'Current password is incorrect' });

    const newHash = await bcrypt.hash(new_password, 14);
    await supabase.from('admins').update({ password_hash: newHash }).eq('id', adminId);

    await logAuditEvent(adminId, 'ADMIN_CHANGE_PASSWORD', {}, req.ip);

    res.json({ success: true, message: 'Password updated successfully' });
  } catch (error) {
    console.error('[Admin Change Password Error]', (error as Error).message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ─── Revoke User Sessions ─────────────────────
router.post('/users/:id/revoke-sessions', async (req, res) => {
  try {
    const userId = req.params.id;

    if (!isValidUUID(userId)) {
      return res.status(400).json({ error: 'Invalid user ID format' });
    }

    await revokeAllUserTokens(userId);

    const adminId = (req as any).admin?.adminId;
    await logAuditEvent(adminId, 'ADMIN_REVOKE_USER_SESSIONS', { targetUser: userId }, req.ip);

    res.json({ success: true, message: 'All user sessions revoked.' });
  } catch (error) {
    console.error('[Revoke Sessions Error]', (error as Error).message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

export default router;
