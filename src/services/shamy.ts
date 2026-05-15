import { supabase } from '../server/db.js';
import { createRequire } from 'module';
import path from 'path';
import crypto from 'crypto';

const require = createRequire(import.meta.url);
const { ShamClient } = require('@jhad-dev/shamy');
const axios = require('axios');

// ============================================================
// إعداد البروكسي الجديد - proxy.mahataplus.com
// المصادقة عبر X-API-Key فقط (بدون تشفير إضافي)
// ============================================================
const SHAMY_PROXY_URL = 'https://proxy.mahataplus.com/';
const SHAMY_API_BASE = 'https://api.shamcash.sy';

const PROXY_API_KEY = process.env.PROXY_API_KEY;

if (!PROXY_API_KEY) {
  throw new Error(
    'PROXY_API_KEY is required. Set it in your .env file.\n' +
    'Example: PROXY_API_KEY=proxy_key_ahmad_nBjJy6BaKM8RbE0esOkzgEG0yuNLcmUQ'
  );
}

axios.interceptors.request.use((config: any) => {
  if (config.url && config.url.startsWith(SHAMY_API_BASE)) {
    const originalUrl = config.url;
    const method = (config.method || 'POST').toUpperCase();
    const headers = config.headers || {};
    const body = config.data
      ? (typeof config.data === 'string' ? JSON.parse(config.data) : config.data)
      : {};

    config.url = SHAMY_PROXY_URL;
    config.method = 'POST';
    config.headers = {
      'Content-Type': 'application/json',
      'X-API-Key': PROXY_API_KEY,
    };
    config.data = JSON.stringify({
      url: originalUrl,
      method,
      headers,
      body,
      follow_redirects: true,
      verify_ssl: true,
    });

    config.transformResponse = [(raw: string) => {
      try {
        const wrapper = JSON.parse(raw);

        // التحقق من خطأ API Key
        if (wrapper.status === 0 && wrapper.error === 'Invalid API key') {
          throw new Error('[PROXY] Invalid API key. Check PROXY_API_KEY in your .env file.');
        }

        // إرجاع محتوى الرد الفعلي
        const responseData = wrapper.response;
        if (typeof responseData === 'string') {
          try {
            return JSON.parse(responseData);
          } catch {
            return responseData;
          }
        }
        return responseData ?? wrapper;
      } catch (err: any) {
        if (err.message?.includes('[PROXY]')) throw err;
        return raw;
      }
    }];
  }
  return config;
});
// ============================================================

// دوال تشفير وفك تشفير session_data باستخدام AES-256-GCM
const SESSION_ENCRYPTION_KEY_HEX = process.env.SESSION_ENCRYPTION_KEY;
if (!SESSION_ENCRYPTION_KEY_HEX) {
  throw new Error('SESSION_ENCRYPTION_KEY environment variable is required. Generate with: node -e "console.log(require(\'crypto\').randomBytes(32).toString(\'hex\'))"');
}
const SESSION_ENCRYPTION_KEY = Buffer.from(SESSION_ENCRYPTION_KEY_HEX, 'hex');
if (SESSION_ENCRYPTION_KEY.length !== 32) {
  throw new Error('SESSION_ENCRYPTION_KEY must be exactly 64 hex characters (32 bytes)');
}

function encryptSessionData(data: object): string {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-gcm', SESSION_ENCRYPTION_KEY, iv);
  const encrypted = Buffer.concat([
    cipher.update(JSON.stringify(data), 'utf8'),
    cipher.final(),
  ]);
  const authTag = cipher.getAuthTag();
  return JSON.stringify({
    iv: iv.toString('hex'),
    data: encrypted.toString('hex'),
    tag: authTag.toString('hex'),
  });
}

function decryptSessionData(encryptedStr: string): any {
  try {
    const { iv, data, tag } = JSON.parse(encryptedStr);
    // [MED-FIX] Validate that iv, data, tag are hex strings before use
    if (typeof iv !== 'string' || typeof data !== 'string' || typeof tag !== 'string') {
      throw new Error('Invalid encrypted session format');
    }
    const decipher = crypto.createDecipheriv(
      'aes-256-gcm',
      SESSION_ENCRYPTION_KEY,
      Buffer.from(iv, 'hex')
    );
    decipher.setAuthTag(Buffer.from(tag, 'hex'));
    const decrypted = Buffer.concat([
      decipher.update(Buffer.from(data, 'hex')),
      decipher.final(),
    ]);
    return JSON.parse(decrypted.toString('utf8'));
  } catch (err) {
    // [MED-FIX] Never surface internal error details — throw generic message only
    throw new Error('Failed to decrypt session data. The session may be corrupted or the encryption key may have changed.');
  }
}

// [CRIT-2 FIX] Whitelist of allowed table names for initiateWalletLink.
// Caller must pass one of these exact values; any other value is rejected.
// This prevents a caller-controlled string from being used as a table name
// even though Supabase's query builder uses it via .from().
const ALLOWED_WALLET_TABLES = new Set(['wallets', 'admin_wallets']);

// pendingLinks يُخزَّن في الذاكرة مع TTL
export const pendingLinks = new Map<string, { data: string; expiresAt: number }>();

setInterval(() => {
  const now = Date.now();
  for (const [key, val] of pendingLinks.entries()) {
    if (val.expiresAt < now) pendingLinks.delete(key);
  }
}, 60 * 1000);

function setPendingLink(walletId: string, data: string) {
  pendingLinks.set(walletId, { data, expiresAt: Date.now() + 10 * 60 * 1000 });
}

function getPendingLink(walletId: string): string | undefined {
  const entry = pendingLinks.get(walletId);
  if (!entry) return undefined;
  if (entry.expiresAt < Date.now()) {
    pendingLinks.delete(walletId);
    return undefined;
  }
  return entry.data;
}

// [CRIT-3 FIX] UUID regex for path-traversal prevention
const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export class ShamCashService {
  static async getClientForWallet(walletId: string, userId: string) {
    const { data: wallet, error } = await supabase
      .from('wallets')
      .select('session_data, status')
      .eq('id', walletId)
      .eq('user_id', userId)
      .single();

    if (error || !wallet) {
      throw new Error('Wallet not found');
    }

    if (!wallet.session_data || wallet.status !== 'active') {
      throw new Error('No valid session data found for this wallet. Please re-link.');
    }

    let sessionData: any;
    if (typeof wallet.session_data === 'string') {
      sessionData = decryptSessionData(wallet.session_data);
    } else {
      sessionData = wallet.session_data;
      console.warn(`[SECURITY] Wallet ${walletId} has unencrypted session data. Will re-encrypt on next login.`);
    }

    const client = new ShamClient();
    client.accessToken = sessionData.accessToken;
    client.token = sessionData.token;
    client.clientKey = sessionData.clientKey;

    return client;
  }

  static initiateWalletLink(walletId: string, userId: string, tableName = 'wallets'): Promise<string> {
    // [CRIT-2 FIX] Reject any tableName that is not in the explicit whitelist.
    // A caller supplying a crafted tableName could otherwise query arbitrary tables.
    if (!ALLOWED_WALLET_TABLES.has(tableName)) {
      return Promise.reject(new Error(`Invalid table name: ${tableName}`));
    }

    // [CRIT-3 FIX] Validate walletId is a proper UUID before using in a file-system path.
    // path.join('/tmp/shamy-sessions', '../../etc/passwd') would escape the intended
    // directory — reject any non-UUID value before construction.
    if (!UUID_REGEX.test(walletId)) {
      return Promise.reject(new Error('Invalid walletId format'));
    }

    return new Promise(async (resolve, reject) => {
      try {
        // Safe: walletId is a validated UUID so no path traversal is possible.
        const sessionDir = path.join('/tmp', 'shamy-sessions', walletId);
        const client = new ShamClient({ sessionDir: sessionDir });

        client.on('qr', (data: any) => {
          setPendingLink(walletId, data);
          resolve(data);
        });

        client.on('ready', async (data: any) => {
          const sessionData = {
            accessToken: client.accessToken,
            token: client.token,
            clientKey: client.clientKey,
            loginTime: new Date().toISOString(),
          };

          const encryptedSession = encryptSessionData(sessionData);

          try {
            let accountNumber = null;
            let walletAddress = null;

            try {
              const profile = await client.account.getMyProfile();
              if (profile) {
                accountNumber = profile.accountNumber || profile.account_number;
                walletAddress = profile.walletAddress || profile.address;
              }
            } catch (e) {
              console.error('Failed to prefetch profile', e);
            }

            // [CRIT-2 FIX] Use if/else on whitelisted values only — never pass tableName
            // directly to .from() without the whitelist check above.
            if (tableName === 'admin_wallets') {
              const { data: updData, error: updErr } = await supabase
                .from('admin_wallets')
                .update({
                  session_data: encryptedSession,
                  status: 'active',
                  updated_at: new Date().toISOString(),
                  ...(accountNumber ? { account_number: String(accountNumber) } : {}),
                  ...(walletAddress ? { wallet_address: String(walletAddress) } : {}),
                })
                .eq('id', walletId)
                .select();

              if (updErr) console.error('admin_wallets Update Error:', updErr);

              if (!updData || updData.length === 0) {
                console.log('No rows updated, attempting insert for admin_wallets:', walletId);
                await supabase.from('admin_wallets').insert({
                  id: walletId,
                  session_data: encryptedSession,
                  status: 'active',
                  name: 'Deposit Wallet',
                  ...(accountNumber ? { account_number: String(accountNumber) } : {}),
                  ...(walletAddress ? { wallet_address: String(walletAddress) } : {}),
                });
              }

              if (walletAddress) {
                await supabase
                  .from('system_settings')
                  .update({ value: String(walletAddress) })
                  .eq('key', 'deposit_wallet_address');
              }
            } else {
              // tableName === 'wallets' (only other whitelisted value)
              await supabase
                .from('wallets')
                .update({
                  session_data: encryptedSession,
                  status: 'active',
                  updated_at: new Date().toISOString(),
                  ...(accountNumber ? { account_number: String(accountNumber) } : {}),
                  ...(walletAddress ? { wallet_address: String(walletAddress) } : {}),
                })
                .eq('id', walletId)
                .eq('user_id', userId);
            }

            pendingLinks.delete(walletId);
          } catch (dbErr) {
            console.error('Failed to update wallet session in DB', dbErr);
          }
        });

        client.on('error', (err: any) => {
          console.error('ShamClient error:', err);
          if (!getPendingLink(walletId)) {
            reject(err);
          }
        });

        await client.initialize();
      } catch (err) {
        reject(err);
      }
    });
  }

  static async getClientForAdminWallet(): Promise<any> {
    const { data: setting } = await supabase
      .from('system_settings')
      .select('value')
      .eq('key', 'deposit_wallet_id')
      .single();

    if (!setting?.value) {
      throw new Error('لم يتم ربط محفظة الإيداع بعد. يرجى ربطها من لوحة الأدمن.');
    }

    const { data: wallet } = await supabase
      .from('admin_wallets')
      .select('session_data, status')
      .eq('id', setting.value)
      .single();

    if (!wallet?.session_data || wallet.status !== 'active') {
      throw new Error('محفظة الإيداع غير نشطة. يرجى إعادة الربط.');
    }

    let sessionData: any;
    if (typeof wallet.session_data === 'string') {
      sessionData = decryptSessionData(wallet.session_data);
    } else {
      sessionData = wallet.session_data;
      console.warn('[SECURITY] Admin wallet has unencrypted session data.');
    }

    const client = new ShamClient();
    client.accessToken = sessionData.accessToken;
    client.token = sessionData.token;
    client.clientKey = sessionData.clientKey;
    return client;
  }

  static async verifyDepositTransaction(tx_id: string): Promise<{
    found: boolean;
    amount_usd?: number;
    amount_raw?: number;
    currency?: string;
  }> {
    const client = await ShamCashService.getClientForAdminWallet();

    const result = await client.history.getLogs(1, 100, {});
    const logs = result.log || result || [];

    const { data: rateSetting } = await supabase
      .from('system_settings')
      .select('value')
      .eq('key', 'syp_to_usd_rate')
      .single();
    const sypRate = Number(rateSetting?.value || 15000);

    let tx = logs.find((log: any) => {
      const isSameTxId = String(log.tranId) === String(tx_id);
      const isIncoming = log.tranKind === 1;
      return isSameTxId && isIncoming;
    });

    if (!tx) {
      try {
        const result2 = await client.history.getLogs(2, 100, {});
        const logs2 = result2.log || result2 || [];
        tx = logs2.find((log: any) => {
          const isSameTxId = String(log.tranId) === String(tx_id);
          const isIncoming = log.tranKind === 1;
          return isSameTxId && isIncoming;
        });
      } catch (e) {
        console.warn('[verifyDepositTransaction] Could not fetch page 2:', e);
      }
    }

    if (!tx) {
      return { found: false };
    }

    let amount_usd = 0;
    if (tx.currencyId === 1) {
      amount_usd = Number(tx.amount);
    } else if (tx.currencyId === 2) {
      amount_usd = Number(tx.amount) / sypRate;
    } else {
      amount_usd = Number(tx.amount);
    }

    return {
      found: true,
      amount_usd: Math.round(amount_usd * 100) / 100,
      amount_raw: Number(tx.amount),
      currency: tx.currencyName || (tx.currencyId === 1 ? 'USD' : 'SYP'),
    };
  }
}
