import express from 'express';
import { supabase } from '../db.js';
import {
  authenticateToken,
  requireActiveSubscription,
  depositRateLimiter,
  transferRateLimiter,
  walletLinkRateLimiter,
  reverifyRateLimiter,
  logAuditEvent,
} from '../middleware.js';
import crypto from 'crypto';
import { z } from 'zod';
import { ShamCashService } from '../../services/shamy.js';

const router = express.Router();

router.use(authenticateToken);

// ─── Validation Schemas ───────────────────────
const upgradeSchema = z.object({
  num_wallets: z.number().int().min(3).max(100),
  num_months: z.number().int().positive().max(12),
});

const transferSchema = z.object({
  peer_account: z.string().min(1).max(255).trim(),
  amount: z.number().positive().max(1000000).finite(),
  currencyId: z.number().int().positive(),
  note: z.string().max(500).optional(),
  pin: z.string().min(4).max(10),
});

const depositRequestSchema = z.object({
  tx_id: z.string().min(1).max(255).trim(),
});

const apiKeySchema = z.object({
  name: z.string().min(1).max(100).trim(),
});

const directionSchema = z.enum(['all', 'in', 'out']).default('all');

// UUID validation
const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
function isValidUUID(id: string): boolean {
  return uuidRegex.test(id);
}

// ─── Subscriptions ────────────────────────────
router.get('/subscription', async (req, res) => {
  try {
    const userId = req.user!.id;
    const { data: sub, error: subError } = await supabase
      .from('subscriptions')
      .select('*')
      .eq('user_id', userId)
      .single();

    if (subError) throw subError;

    const { count: activeWallets, error: walletError } = await supabase
      .from('wallets')
      .select('id', { count: 'exact', head: true })
      .eq('user_id', userId)
      .eq('status', 'active');

    if (walletError) throw walletError;

    res.json({ ...sub, active_wallets_count: activeWallets || 0 });
  } catch (error) {
    console.error('[Subscription Get Error]', (error as Error).message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.post('/subscription/upgrade', async (req, res) => {
  try {
    const userId = req.user!.id;

    const parseResult = upgradeSchema.safeParse(req.body);
    if (!parseResult.success) {
      return res.status(400).json({ error: parseResult.error.errors[0].message });
    }
    const { num_wallets, num_months } = parseResult.data;

    const cost = num_wallets * num_months * 0.50;

    const { data: sub, error: subError } = await supabase
      .from('subscriptions')
      .select('*')
      .eq('user_id', userId)
      .single();

    if (subError) throw subError;

    if (Number(sub.current_balance) < cost) {
      return res.status(400).json({ error: 'Insufficient balance' });
    }

    const newBalance = Number(sub.current_balance) - cost;
    const currentExpiry = sub.expires_at ? new Date(sub.expires_at) : new Date();
    const baseDate = currentExpiry > new Date() ? currentExpiry : new Date();
    baseDate.setMonth(baseDate.getMonth() + num_months);

    const { data: newSub, error: updateError } = await supabase
      .from('subscriptions')
      .update({
        current_balance: newBalance,
        max_wallets: num_wallets,
        expires_at: baseDate.toISOString(),
        status: 'active',
      })
      .eq('user_id', userId)
      .select('*')
      .single();

    if (updateError) throw updateError;

    await logAuditEvent(userId, 'SUBSCRIPTION_UPGRADE', { num_wallets, num_months, cost }, req.ip);

    res.json(newSub);
  } catch (error) {
    console.error('[Subscription Upgrade Error]', (error as Error).message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.post('/subscription/toggle-auto-renew', async (req, res) => {
  try {
    const userId = req.user!.id;
    const schema = z.object({ auto_renew: z.boolean() });
    const parseResult = schema.safeParse(req.body);
    if (!parseResult.success) {
      return res.status(400).json({ error: 'auto_renew must be a boolean' });
    }
    const { auto_renew } = parseResult.data;

    const { error } = await supabase
      .from('subscriptions')
      .update({ auto_renew })
      .eq('user_id', userId);

    if (error) throw error;
    res.json({ success: true, auto_renew });
  } catch (error) {
    console.error('[Auto Renew Toggle Error]', (error as Error).message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ─── Wallets ──────────────────────────────────
router.get('/wallets', async (req, res) => {
  try {
    const userId = req.user!.id;
    const { data, error } = await supabase
      .from('wallets')
      .select('id, wallet_address, account_number, name, status, created_at, updated_at')
      .eq('user_id', userId);

    if (error) throw error;
    res.json(data);
  } catch (error) {
    console.error('[Wallets Get Error]', (error as Error).message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.post('/wallets/link/init', walletLinkRateLimiter, async (req, res) => {
  try {
    const userId = req.user!.id;
    const schema = z.object({ name: z.string().max(100).optional() });
    const parseResult = schema.safeParse(req.body);
    if (!parseResult.success) {
      return res.status(400).json({ error: parseResult.error.errors[0].message });
    }
    const { name } = parseResult.data;

    const { data: sub } = await supabase
      .from('subscriptions')
      .select('max_wallets, status')
      .eq('user_id', userId)
      .single();

    if (!sub || sub.status !== 'active') {
      return res.status(403).json({ error: 'Subscription is not active' });
    }

    const { count: activeWallets } = await supabase
      .from('wallets')
      .select('id', { count: 'exact', head: true })
      .eq('user_id', userId)
      .eq('status', 'active');

    if (activeWallets && activeWallets >= sub.max_wallets) {
      return res.status(403).json({ error: 'Upgrade your subscription to add more wallets' });
    }

    await supabase
      .from('wallets')
      .delete()
      .eq('user_id', userId)
      .eq('status', 'pending')
      .lt('created_at', new Date(Date.now() - 30 * 60 * 1000).toISOString());

    const { data: wallet, error } = await supabase
      .from('wallets')
      .insert({
        user_id: userId,
        name: name || 'My ShamCash Wallet',
        wallet_address: null,
        account_number: null,
        status: 'pending',
      })
      .select('id')
      .single();

    if (error) throw error;

    const qrPayload = await ShamCashService.initiateWalletLink(wallet.id, userId);
    res.json({ walletId: wallet.id, qrPayload });
  } catch (error) {
    console.error('[Wallet Link Init Error]', (error as Error).message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.get('/wallets/link/status/:walletId', async (req, res) => {
  try {
    const userId = req.user!.id;
    const { walletId } = req.params;

    if (!isValidUUID(walletId)) {
      return res.status(400).json({ error: 'Invalid wallet ID format' });
    }

    const { data: wallet, error } = await supabase
      .from('wallets')
      .select('status')
      .eq('id', walletId)
      .eq('user_id', userId)
      .single();

    if (error) throw error;
    res.json({ linked: wallet.status === 'active' });
  } catch (error) {
    console.error('[Wallet Link Status Error]', (error as Error).message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.delete('/wallets/:id', async (req, res) => {
  try {
    const userId = req.user!.id;

    if (!isValidUUID(req.params.id)) {
      return res.status(400).json({ error: 'Invalid wallet ID format' });
    }

    const { error } = await supabase
      .from('wallets')
      .delete()
      .eq('id', req.params.id)
      .eq('user_id', userId);

    if (error) throw error;

    await logAuditEvent(userId, 'WALLET_DELETED', { walletId: req.params.id }, req.ip);

    res.json({ success: true });
  } catch (error) {
    console.error('[Wallet Delete Error]', (error as Error).message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ─── Wallet Actions ───────────────────────────
router.get('/wallets/:id/balance', requireActiveSubscription, async (req, res) => {
  try {
    const userId = req.user!.id;

    if (!isValidUUID(req.params.id)) {
      return res.status(400).json({ error: 'Invalid wallet ID format' });
    }

    const client = await ShamCashService.getClientForWallet(req.params.id, userId);
    const balances = await client.account.getBalances();
    res.json(balances);
  } catch (error) {
    if ((error as Error).message?.includes('401')) {
      const userId = req.user!.id;
      await supabase
        .from('wallets')
        .update({ status: 'expired' })
        .eq('id', req.params.id)
        .eq('user_id', userId);
    }
    console.error('[Wallet Balance Error]', (error as Error).message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.get('/wallets/:id/profile', requireActiveSubscription, async (req, res) => {
  try {
    const userId = req.user!.id;

    if (!isValidUUID(req.params.id)) {
      return res.status(400).json({ error: 'Invalid wallet ID format' });
    }

    const client = await ShamCashService.getClientForWallet(req.params.id, userId);
    const profile = await client.account.getMyProfile();
    res.json(profile);
  } catch (error) {
    console.error('[Wallet Profile Error]', (error as Error).message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.get('/wallets/:id/transactions', requireActiveSubscription, async (req, res) => {
  try {
    const userId = req.user!.id;

    if (!isValidUUID(req.params.id)) {
      return res.status(400).json({ error: 'Invalid wallet ID format' });
    }

    const { page = '1', limit = '20' } = req.query;

    const directionParsed = directionSchema.safeParse(req.query.direction ?? 'all');
    const direction = directionParsed.success ? directionParsed.data : 'all';

    const safePage = Math.max(1, Number(page));
    const safeLimit = Math.min(100, Math.max(1, Number(limit)));

    const client = await ShamCashService.getClientForWallet(req.params.id, userId);
    const tx = await client.history.getLogs(safePage, safeLimit, { direction });
    res.json(tx);
  } catch (error) {
    console.error('[Wallet Transactions Error]', (error as Error).message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.post('/wallets/:id/transfer', requireActiveSubscription, transferRateLimiter, async (req, res) => {
  try {
    const userId = req.user!.id;

    if (!isValidUUID(req.params.id)) {
      return res.status(400).json({ error: 'Invalid wallet ID format' });
    }

    const parseResult = transferSchema.safeParse(req.body);
    if (!parseResult.success) {
      return res.status(400).json({ error: parseResult.error.errors[0].message });
    }
    const { peer_account, amount, currencyId, note, pin } = parseResult.data;

    const client = await ShamCashService.getClientForWallet(req.params.id, userId);
    const result = await client.transfer.executeTransaction(
      peer_account, amount, currencyId, note || '', pin
    );

    // SECURITY: pin is intentionally excluded from audit log
    await logAuditEvent(userId, 'WALLET_TRANSFER', {
      walletId: req.params.id,
      peer_account,
      amount,
      currencyId,
    }, req.ip);

    res.json(result);
  } catch (error) {
    // SECURITY: never expose internal error details to client
    console.error('[Wallet Transfer Error]', { message: (error as Error).message, walletId: req.params.id });
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.post('/wallets/:id/resolve-account', requireActiveSubscription, async (req, res) => {
  try {
    const userId = req.user!.id;

    if (!isValidUUID(req.params.id)) {
      return res.status(400).json({ error: 'Invalid wallet ID format' });
    }

    const schema = z.object({ address: z.string().min(1).max(255).trim() });
    const parseResult = schema.safeParse(req.body);
    if (!parseResult.success) {
      return res.status(400).json({ error: parseResult.error.errors[0].message });
    }
    const { address } = parseResult.data;

    const client = await ShamCashService.getClientForWallet(req.params.id, userId);
    const result = await client.transfer.resolveAccount(address);
    res.json(result);
  } catch (error) {
    console.error('[Resolve Account Error]', (error as Error).message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ─── Deposits ─────────────────────────────────
router.get('/settings/exchange-rate', async (req, res) => {
  try {
    const { data: settings } = await supabase
      .from('system_settings')
      .select('key, value')
      .in('key', ['syp_to_usd_rate', 'deposit_wallet_address']);

    let rate = 15000;
    let depositAddress = null;

    settings?.forEach(s => {
      if (s.key === 'syp_to_usd_rate') rate = Number(s.value) || 15000;
      if (s.key === 'deposit_wallet_address' && s.value) depositAddress = s.value;
    });

    res.json({ success: true, syp_to_usd_rate: rate, deposit_wallet_address: depositAddress });
  } catch (error) {
    console.error('[Exchange Rate Error]', (error as Error).message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.post('/deposit/request', depositRateLimiter, async (req, res) => {
  try {
    const userId = req.user!.id;

    const parseResult = depositRequestSchema.safeParse(req.body);
    if (!parseResult.success) {
      return res.status(400).json({ error: parseResult.error.errors[0].message });
    }
    const { tx_id } = parseResult.data;

    const { data: existing } = await supabase
      .from('deposit_requests')
      .select('id, status')
      .eq('tx_id', tx_id)
      .maybeSingle();

    if (existing) {
      if (existing.status === 'pending_verification') {
        return res.status(400).json({ error: 'This transaction is already being verified.' });
      }
      return res.status(400).json({ error: 'Transaction ID already registered' });
    }

    let status = 'pending_verification';
    let amount_usd = null;
    let message = 'Transaction not found yet. Verification will be attempted shortly.';
    let success = false;

    try {
      const verification = await ShamCashService.verifyDepositTransaction(tx_id);
      if (verification.found && verification.amount_usd) {
        status = 'approved';
        amount_usd = verification.amount_usd;
        success = true;
        message = `$${amount_usd} added to your balance!`;

        // SECURITY: Use atomic RPC to prevent double-credit race condition
        const { error: balanceErr } = await supabase.rpc('add_user_balance', {
          p_user_id: userId,
          p_amount: amount_usd,
        });

        if (balanceErr) throw balanceErr;
      }
    } catch (e: any) {
      if (
        e.message?.includes('لم يتم ربط محفظة الإيداع بعد') ||
        e.message?.includes('محفظة الإيداع غير نشطة')
      ) {
        console.warn('[Deposit Request] Auto-verification skipped:', e.message);
        status = 'pending';
      } else {
        console.error('Auto verification failed', e.message);
      }
    }

    const { error: insertErr } = await supabase.from('deposit_requests').insert({
      user_id: userId,
      tx_id,
      amount_usd: amount_usd || 0,
      status,
      ...(status === 'approved' ? { reviewed_at: new Date().toISOString() } : {}),
    });

    if (insertErr) throw insertErr;

    await logAuditEvent(userId, 'DEPOSIT_REQUEST', { tx_id, status, amount_usd }, req.ip);

    res.json({ success, message, amount_usd, status });
  } catch (error) {
    console.error('[Deposit Request Error]', (error as Error).message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// SECURITY: reverifyRateLimiter added to prevent flooding reverify endpoint
router.post('/deposit/reverify', reverifyRateLimiter, async (req, res) => {
  try {
    const userId = req.user!.id;

    const parseResult = depositRequestSchema.safeParse(req.body);
    if (!parseResult.success) {
      return res.status(400).json({ error: parseResult.error.errors[0].message });
    }
    const { tx_id } = parseResult.data;

    const { data: reqData } = await supabase
      .from('deposit_requests')
      .select('id, status')
      .eq('tx_id', tx_id)
      .eq('user_id', userId)
      .single();

    if (!reqData || reqData.status !== 'pending_verification') {
      return res.status(400).json({ error: 'Request not found or does not need verification' });
    }

    try {
      const verification = await ShamCashService.verifyDepositTransaction(tx_id);

      if (verification.found && verification.amount_usd) {
        // SECURITY: Atomic update — only succeeds if status is still pending_verification
        const { data: updated, error: updateErr } = await supabase
          .from('deposit_requests')
          .update({
            status: 'approved',
            amount_usd: verification.amount_usd,
            reviewed_at: new Date().toISOString(),
          })
          .eq('id', reqData.id)
          .eq('status', 'pending_verification')
          .select('id');

        if (updateErr) throw updateErr;

        if (!updated || updated.length === 0) {
          return res.status(409).json({ error: 'This request has already been processed.' });
        }

        const { error: balanceErr } = await supabase.rpc('add_user_balance', {
          p_user_id: userId,
          p_amount: verification.amount_usd,
        });

        if (balanceErr) throw balanceErr;

        return res.json({
          success: true,
          message: `Verified! $${verification.amount_usd} added to your balance.`,
        });
      } else {
        return res.json({ success: false, message: 'Transaction not found yet.' });
      }
    } catch (e: any) {
      if (
        e.message?.includes('لم يتم ربط محفظة الإيداع بعد') ||
        e.message?.includes('محفظة الإيداع غير نشطة')
      ) {
        return res.status(400).json({
          error: 'Auto-verification is currently disabled. Please wait for manual admin review.',
        });
      }
      console.error('Reverify failed', e.message);
      return res.status(500).json({ error: 'Internal server error' });
    }
  } catch (error) {
    console.error('[Deposit Reverify Error]', (error as Error).message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.get('/deposit/requests', async (req, res) => {
  try {
    const userId = req.user!.id;
    const { data, error } = await supabase
      .from('deposit_requests')
      .select('*')
      .eq('user_id', userId)
      .order('created_at', { ascending: false });

    if (error) throw error;
    res.json(data);
  } catch (error) {
    console.error('[Deposit Requests Error]', (error as Error).message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ─── API Keys ─────────────────────────────────
router.get('/api-keys', async (req, res) => {
  try {
    const userId = req.user!.id;
    const { data, error } = await supabase
      .from('api_keys')
      .select('id, name, key_prefix, created_at, last_used_at')
      .eq('user_id', userId)
      .order('created_at', { ascending: false });

    if (error) throw error;
    res.json(data);
  } catch (error) {
    console.error('[API Keys Get Error]', (error as Error).message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.post('/api-keys', async (req, res) => {
  try {
    const userId = req.user!.id;

    const parseResult = apiKeySchema.safeParse(req.body);
    if (!parseResult.success) {
      return res.status(400).json({ error: parseResult.error.errors[0].message });
    }
    const { name } = parseResult.data;

    const { count: existingKeys } = await supabase
      .from('api_keys')
      .select('id', { count: 'exact', head: true })
      .eq('user_id', userId);

    if (existingKeys && existingKeys >= 10) {
      return res.status(400).json({ error: 'Maximum of 10 API keys allowed' });
    }

    const rawKey = 'sk_' + crypto.randomBytes(32).toString('hex');
    const keyHash = crypto.createHash('sha256').update(rawKey).digest('hex');
    const keyPrefix = rawKey.substring(0, 8) + '...' + rawKey.substring(rawKey.length - 4);

    const { data, error } = await supabase
      .from('api_keys')
      .insert({ user_id: userId, name, key_hash: keyHash, key_prefix: keyPrefix })
      .select('id, name, key_prefix, created_at')
      .single();

    if (error) throw error;

    await logAuditEvent(userId, 'API_KEY_CREATED', { name, keyPrefix }, req.ip);

    res.json({ ...data, rawKey });
  } catch (error) {
    console.error('[API Key Create Error]', (error as Error).message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.delete('/api-keys/:id', async (req, res) => {
  try {
    const userId = req.user!.id;

    if (!isValidUUID(req.params.id)) {
      return res.status(400).json({ error: 'Invalid key ID format' });
    }

    const { error } = await supabase
      .from('api_keys')
      .delete()
      .eq('id', req.params.id)
      .eq('user_id', userId);

    if (error) throw error;

    await logAuditEvent(userId, 'API_KEY_DELETED', { keyId: req.params.id }, req.ip);

    res.json({ success: true });
  } catch (error) {
    console.error('[API Key Delete Error]', (error as Error).message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

export default router;
