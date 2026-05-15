import express from 'express';
import { supabase } from '../db.js';
import { authenticateApiKey, logAuditEvent, transferRateLimiter } from '../middleware.js';
import { ShamCashService } from '../../services/shamy.js';
import { z } from 'zod';

const router = express.Router();

router.use(authenticateApiKey);

// ─── Validation Schemas ───────────────────────
const transferSchema = z.object({
  recipientAddress: z.string().min(1).max(255).trim(),
  amount: z.number().positive().max(1000000).finite(),
  currencyId: z.number().int().positive(),
  note: z.string().max(500).optional(),
  pin: z.string().min(4).max(10),
});

const directionSchema = z.enum(['all', 'in', 'out']).default('all');

// UUID validation
const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

// ─── Wallet lookup helper ─────────────────────
// SECURITY: Uses separate queries instead of raw string interpolation in .or()
// to prevent potential injection via wallet address parameter.
async function getWalletByAddress(address: string, userId: string) {
  // Try UUID lookup first
  if (uuidRegex.test(address)) {
    const { data: walletById } = await supabase
      .from('wallets')
      .select('id, status')
      .eq('user_id', userId)
      .eq('id', address)
      .single();
    if (walletById) return walletById;
  }

  // Try wallet_address exact match (parameterized — safe)
  const { data: byWalletAddr } = await supabase
    .from('wallets')
    .select('id, status')
    .eq('user_id', userId)
    .eq('wallet_address', address)
    .maybeSingle();
  if (byWalletAddr) return byWalletAddr;

  // Try account_number exact match (parameterized — safe)
  const { data: byAccountNum } = await supabase
    .from('wallets')
    .select('id, status')
    .eq('user_id', userId)
    .eq('account_number', address)
    .maybeSingle();
  if (byAccountNum) return byAccountNum;

  return null;
}

// ─── 1. Get all wallets ───────────────────────
router.get('/wallets', async (req, res) => {
  try {
    const userId = req.apiKeyUser?.id;
    const { data: wallets, error } = await supabase
      .from('wallets')
      .select('id, wallet_address, account_number, name, status, created_at')
      .eq('user_id', userId);

    if (error) throw error;

    const formattedWallets = wallets.map(w => ({
      id: w.id,
      provider: 'shamcash',
      providerDisplayName: 'ShamCash',
      label: w.name || null,
      phone: null,
      walletAddress: w.wallet_address,
      accountNumber: w.account_number,
      region: null,
      status: w.status,
    }));

    res.json(formattedWallets);
  } catch (error) {
    console.error('[External API Wallets Error]', (error as Error).message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ─── 2. Wallet balances ───────────────────────
router.get('/wallets/shamcash/:walletAddress/balance', async (req, res) => {
  try {
    const userId = req.apiKeyUser!.id;
    const { walletAddress } = req.params;

    // SECURITY: Enforce reasonable length on path parameter
    if (!walletAddress || walletAddress.length > 255) {
      return res.status(400).json({ error: 'INVALID_ADDRESS', message: 'Invalid wallet address' });
    }

    const wallet = await getWalletByAddress(walletAddress, userId);
    if (!wallet) return res.status(404).json({ error: 'NOT_FOUND', message: 'Wallet not found' });
    if (wallet.status !== 'active') {
      return res.status(401).json({ error: 'WALLET_SESSION_EXPIRED', message: 'Wallet session expired' });
    }

    const client = await ShamCashService.getClientForWallet(wallet.id, userId);
    const balancesResponse = await client.account.getBalances();

    const formattedBalances = (balancesResponse.balances || balancesResponse || []).map((b: any) => ({
      currency:
        b.currencyName ||
        (b.currencyId === 1 ? 'USD' : b.currencyId === 2 ? 'SYP' : b.currencyId === 3 ? 'EUR' : 'UNK'),
      amount: Number(b.amount || b.balance || b.money || 0),
      label: null,
    }));

    res.json(formattedBalances);
  } catch (error) {
    console.error('[External API Balance Error]', (error as Error).message);
    res.status(502).json({ error: 'WALLET_UPSTREAM_ERROR', message: 'Upstream error' });
  }
});

// ─── 3. Transaction history ───────────────────
router.get('/wallets/shamcash/:walletAddress/transactions', async (req, res) => {
  try {
    const userId = req.apiKeyUser!.id;
    const { walletAddress } = req.params;

    if (!walletAddress || walletAddress.length > 255) {
      return res.status(400).json({ error: 'INVALID_ADDRESS', message: 'Invalid wallet address' });
    }

    const { page = '1', limit = '50' } = req.query;

    const directionParsed = directionSchema.safeParse(req.query.direction ?? 'all');
    const direction = directionParsed.success ? directionParsed.data : 'all';

    const safePage = Math.max(1, Number(page));
    const safeLimit = Math.min(100, Math.max(1, Number(limit)));

    const wallet = await getWalletByAddress(walletAddress, userId);
    if (!wallet) return res.status(404).json({ error: 'NOT_FOUND', message: 'Wallet not found' });

    const client = await ShamCashService.getClientForWallet(wallet.id, userId);
    const logs = await client.history.getLogs(safePage, safeLimit, { direction });

    let rawTransactions = Array.isArray(logs) ? logs : logs.log || [];

    if (direction === 'in') {
      rawTransactions = rawTransactions.filter(
        (t: any) => t.tranKind === 1 || t.type === 'in' || t.type === 'income'
      );
    } else if (direction === 'out') {
      rawTransactions = rawTransactions.filter(
        (t: any) => t.tranKind === 2 || t.type === 'out' || t.type === 'outgoing'
      );
    }

    const formattedLogs = rawTransactions.map((t: any) => {
      const isIncoming = t.tranKind === 1 || t.type === 'in' || t.type === 'income';
      const dateStr = t.tranDate;
      const timeStr = t.tranTime;
      let occurredAt = null;
      if (dateStr && timeStr) occurredAt = `${dateStr}T${timeStr}`;
      return {
        id: t.tranId?.toString() || t.id?.toString(),
        type: isIncoming ? 'credit' : 'debit',
        amount: Number(t.amount || 0),
        currency: t.currencyName || t.currency || 'SYP',
        counterparty: t.peerUserName || t.peer || t.peerAccountInfo?.name || null,
        description: t.note || null,
        status: null,
        occurredAt,
      };
    });

    res.json(formattedLogs);
  } catch (error) {
    console.error('[External API Transactions Error]', (error as Error).message);
    res.status(502).json({ error: 'WALLET_UPSTREAM_ERROR', message: 'Upstream error' });
  }
});

// ─── 4. QR Code ───────────────────────────────
router.get('/wallets/shamcash/:walletAddress/qr', async (req, res) => {
  try {
    const userId = req.apiKeyUser!.id;
    const { walletAddress } = req.params;

    if (!walletAddress || walletAddress.length > 255) {
      return res.status(400).json({ error: 'INVALID_ADDRESS', message: 'Invalid wallet address' });
    }

    const { data: wallet } = await supabase
      .from('wallets')
      .select('id, wallet_address')
      .eq('user_id', userId)
      .eq('wallet_address', walletAddress)  // SECURITY: parameterized exact match
      .single();

    if (!wallet) return res.status(404).json({ error: 'NOT_FOUND', message: 'Wallet not found' });

    const client = await ShamCashService.getClientForWallet(wallet.id, userId);
    const profile = await client.account.getMyProfile();

    const qrData =
      profile.qrCode || profile.qr_code || profile.qr || profile.qrData || btoa(JSON.stringify(profile));

    res.json({
      success: true,
      address: profile.address || profile.walletAddress || walletAddress,
      qr_data: qrData,
    });
  } catch (error) {
    if ((error as any).response?.data?.error === 'INVALID_SESSION') {
      return res.status(401).json({
        error: 'INVALID_SESSION',
        message: 'Session expired. Please reconnect wallet in dashboard.',
      });
    }
    console.error('[External API QR Error]', (error as Error).message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ─── 5. Transfer money ────────────────────────
router.post('/wallets/shamcash/:walletAddress/transfer', transferRateLimiter, async (req, res) => {
  try {
    const userId = req.apiKeyUser!.id;
    const { walletAddress } = req.params;

    if (!walletAddress || walletAddress.length > 255) {
      return res.status(400).json({ error: 'INVALID_ADDRESS', message: 'Invalid wallet address' });
    }

    const parseResult = transferSchema.safeParse(req.body);
    if (!parseResult.success) {
      return res.status(400).json({
        error: 'VALIDATION_ERROR',
        message: parseResult.error.errors[0].message,
      });
    }
    const { recipientAddress, amount, currencyId, note, pin } = parseResult.data;

    const wallet = await getWalletByAddress(walletAddress, userId);
    if (!wallet) return res.status(404).json({ error: 'NOT_FOUND', message: 'Wallet not found' });

    const client = await ShamCashService.getClientForWallet(wallet.id, userId);

    const result = await client.transfer.executeTransaction(
      recipientAddress, amount, currencyId, note || '', pin
    );

    // SECURITY: pin intentionally excluded from audit log
    await logAuditEvent(userId, 'EXTERNAL_API_TRANSFER', {
      walletAddress,
      recipientAddress,
      amount,
      currencyId,
    });

    res.json({ success: true, message: 'Transfer completed successfully', rawData: result });
  } catch (error) {
    console.error('[External API Transfer Error]', (error as Error).message);
    res.status(502).json({ error: 'PROVIDER_ERROR', message: 'Upstream error' });
  }
});

export default router;
