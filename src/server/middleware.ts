import jwt from 'jsonwebtoken';
import { Request, Response, NextFunction } from 'express';
import { supabase } from './db.js';
import crypto from 'crypto';

const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) throw new Error('JWT_SECRET environment variable is required');

declare global {
  namespace Express {
    interface Request {
      user?: { id: string; email: string };
      apiKeyUser?: { id: string };
    }
  }
}

// ─────────────────────────────────────────────
// Audit Log (sanitized — never logs sensitive fields)
// ─────────────────────────────────────────────
export async function logAuditEvent(
  userId: string | null,
  action: string,
  details: Record<string, any>,
  ipAddress?: string
) {
  try {
    const sanitized = Object.fromEntries(
      Object.entries(details).filter(([key]) => !/(pin|password|secret|token)/i.test(key))
    );

    const detailsStr = JSON.stringify(sanitized);
    const sanitizedDetails = detailsStr.length > 4096
      ? { ...JSON.parse(detailsStr.substring(0, 4000)), _truncated: true }
      : sanitized;

    await supabase.from('audit_logs').insert({
      user_id: userId,
      action,
      details: sanitizedDetails,
      ip_address: ipAddress || null,
    });
  } catch (err) {
    console.error('[Audit Log Error]', (err as Error).message);
  }
}

// ─────────────────────────────────────────────
// Subscription Auto-Renew
// ─────────────────────────────────────────────
export async function checkAndAutoRenewSubscription(userId: string) {
  const { data: sub } = await supabase
    .from('subscriptions')
    .select('*')
    .eq('user_id', userId)
    .single();

  if (!sub) return false;

  const now = new Date();
  const expiresAt = new Date(sub.expires_at);

  if (expiresAt < now) {
    if (sub.auto_renew) {
      // [LOW-FIX] Use integer arithmetic (cents) to avoid floating-point precision errors
      // in financial calculations.  0.50 USD = 50 cents.
      const costCents = sub.max_wallets * 50;
      const balanceCents = Math.round(Number(sub.current_balance) * 100);

      if (balanceCents >= costCents) {
        const newBalanceCents = balanceCents - costCents;
        const newExpiresAt = new Date();
        newExpiresAt.setMonth(newExpiresAt.getMonth() + 1);
        await supabase
          .from('subscriptions')
          .update({
            current_balance: newBalanceCents / 100,
            expires_at: newExpiresAt.toISOString(),
            status: 'active',
          })
          .eq('id', sub.id);
        return true;
      } else {
        await supabase
          .from('subscriptions')
          .update({ auto_renew: false, status: 'expired' })
          .eq('id', sub.id);
        return false;
      }
    } else {
      await supabase.from('subscriptions').update({ status: 'expired' }).eq('id', sub.id);
      return false;
    }
  }

  return true;
}

// ─────────────────────────────────────────────
// JWT Authentication
// ─────────────────────────────────────────────
export const authenticateToken = (req: Request, res: Response, next: NextFunction) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    res.status(401).json({ error: 'Missing token' });
    return;
  }

  jwt.verify(token, JWT_SECRET!, (err, user) => {
    if (err) {
      res.status(403).json({ error: 'Invalid or expired token' });
      return;
    }
    req.user = user as { id: string; email: string };
    next();
  });
};

// ─────────────────────────────────────────────
// Secure IP extraction
// SECURITY: Only trust the real IP from the socket when behind a trusted proxy.
// Never trust X-Forwarded-For from untrusted clients to prevent rate limit bypass.
// When trust proxy = 1 is set in Express, req.ip already resolves correctly.
// ─────────────────────────────────────────────
export function getClientIP(req: Request): string {
  // In production with trust proxy enabled, req.ip is already the real client IP.
  // In dev, fall back to socket address.
  return req.ip || req.socket.remoteAddress || 'unknown';
}

// ─────────────────────────────────────────────
// Robust In-Memory Rate Limiter
// Handles cleanup, sets standard Retry-After headers, and is not bypassable
// via arbitrary X-Forwarded-For headers (IP is resolved by Express trust proxy setting).
// ─────────────────────────────────────────────
interface RateLimitRecord {
  count: number;
  resetAt: number;
}

class InMemoryRateLimiter {
  private store = new Map<string, RateLimitRecord>();

  check(key: string, maxAttempts: number, windowMs: number): { allowed: boolean; retryAfterMs: number } {
    const now = Date.now();
    const record = this.store.get(key);

    if (record && record.resetAt > now) {
      if (record.count >= maxAttempts) {
        return { allowed: false, retryAfterMs: record.resetAt - now };
      }
      record.count++;
      return { allowed: true, retryAfterMs: 0 };
    }

    this.store.set(key, { count: 1, resetAt: now + windowMs });
    return { allowed: true, retryAfterMs: 0 };
  }

  cleanup() {
    const now = Date.now();
    for (const [key, record] of this.store.entries()) {
      if (record.resetAt <= now) this.store.delete(key);
    }
  }
}

// Warn in production if Redis is not configured
if (process.env.NODE_ENV === 'production' && !process.env.REDIS_URL) {
  console.warn(
    '[SECURITY WARNING] REDIS_URL not set. Using in-memory rate limiting. ' +
    'This does NOT work across multiple processes. Set REDIS_URL for distributed deployments.'
  );
}

export const rateLimiter = new InMemoryRateLimiter();
// Clean up expired entries every 5 minutes
setInterval(() => rateLimiter.cleanup(), 5 * 60 * 1000).unref();

// ─────────────────────────────────────────────
// Global API Rate Limiter — 200 req/min per IP (prevents DoS on all /api/* routes)
// ─────────────────────────────────────────────
export const globalApiRateLimiter = (req: Request, res: Response, next: NextFunction) => {
  const ip = getClientIP(req);
  const result = rateLimiter.check(`global:${ip}`, 200, 60 * 1000);
  if (!result.allowed) {
    res.setHeader('Retry-After', Math.ceil(result.retryAfterMs / 1000).toString());
    res.setHeader('X-RateLimit-Limit', '200');
    res.setHeader('X-RateLimit-Remaining', '0');
    return res.status(429).json({ error: 'Too many requests. Please slow down.' });
  }
  next();
};

// ─────────────────────────────────────────────
// Login Rate Limiter — 5 attempts / 1 min per IP
// ─────────────────────────────────────────────
export const loginRateLimiter = (req: Request, res: Response, next: NextFunction) => {
  const ip = getClientIP(req);
  const result = rateLimiter.check(`login:${ip}`, 5, 60 * 1000);
  if (!result.allowed) {
    logAuditEvent(null, 'LOGIN_RATE_LIMIT_HIT', { ip }, ip);
    res.setHeader('Retry-After', Math.ceil(result.retryAfterMs / 1000).toString());
    return res.status(429).json({ error: 'Too many login attempts. Please try again in 1 minute.' });
  }
  next();
};

// ─────────────────────────────────────────────
// OTP Send Rate Limiter — 3 OTPs / 10 min per IP (prevents email spam)
// ─────────────────────────────────────────────
export const otpSendRateLimiter = (req: Request, res: Response, next: NextFunction) => {
  const ip = getClientIP(req);
  const result = rateLimiter.check(`otp_send:${ip}`, 3, 10 * 60 * 1000);
  if (!result.allowed) {
    res.setHeader('Retry-After', Math.ceil(result.retryAfterMs / 1000).toString());
    return res.status(429).json({ error: 'Too many OTP requests. Please try again in 10 minutes.' });
  }
  next();
};

// ─────────────────────────────────────────────
// [HIGH-FIX] OTP Email Rate Limiter — 3 OTPs / 10 min per EMAIL ADDRESS.
// IP-only rate limiting can be bypassed by rotating IPs (proxies, VPNs, botnets).
// Adding per-email limiting ensures a single target email cannot be flooded
// regardless of how many source IPs an attacker controls.
// ─────────────────────────────────────────────
export const otpEmailRateLimiter = (email: string): boolean => {
  if (!email || typeof email !== 'string') return false;
  const result = rateLimiter.check(`otp_email:${email.toLowerCase()}`, 3, 10 * 60 * 1000);
  return result.allowed;
};

// ─────────────────────────────────────────────
// Admin Login Rate Limiter — 3 attempts / 15 min per IP
// ─────────────────────────────────────────────
export const adminLoginRateLimiter = (req: Request, res: Response, next: NextFunction) => {
  const ip = getClientIP(req);
  const result = rateLimiter.check(`admin_login:${ip}`, 3, 15 * 60 * 1000);
  if (!result.allowed) {
    logAuditEvent(null, 'ADMIN_LOGIN_BRUTE_FORCE', { ip }, ip);
    res.setHeader('Retry-After', Math.ceil(result.retryAfterMs / 1000).toString());
    return res.status(429).json({ error: 'Too many attempts. Try again in 15 minutes.' });
  }
  next();
};

// ─────────────────────────────────────────────
// Transfer Rate Limiter — 10 req / 1 min per user
// ─────────────────────────────────────────────
export const transferRateLimiter = (req: Request, res: Response, next: NextFunction) => {
  const userId = req.user?.id || req.apiKeyUser?.id || getClientIP(req);
  const result = rateLimiter.check(`transfer:${userId}`, 10, 60 * 1000);
  if (!result.allowed) {
    logAuditEvent(userId, 'TRANSFER_RATE_LIMIT_HIT', {}, getClientIP(req));
    res.setHeader('Retry-After', Math.ceil(result.retryAfterMs / 1000).toString());
    return res.status(429).json({ error: 'Too many transfer requests. Try again in 1 minute.' });
  }
  next();
};

// ─────────────────────────────────────────────
// Wallet Link Rate Limiter — 5 req / 1 hour per user
// ─────────────────────────────────────────────
export const walletLinkRateLimiter = (req: Request, res: Response, next: NextFunction) => {
  const userId = req.user?.id || getClientIP(req);
  const result = rateLimiter.check(`wallet_link:${userId}`, 5, 60 * 60 * 1000);
  if (!result.allowed) {
    logAuditEvent(userId, 'WALLET_LINK_RATE_LIMIT_HIT', {}, getClientIP(req));
    res.setHeader('Retry-After', Math.ceil(result.retryAfterMs / 1000).toString());
    return res.status(429).json({ error: 'Too many wallet link attempts. Try again in 1 hour.' });
  }
  next();
};

// ─────────────────────────────────────────────
// Deposit Rate Limiter — 3 req / 10 min per user
// ─────────────────────────────────────────────
export const depositRateLimiter = (req: Request, res: Response, next: NextFunction) => {
  const userId = req.user?.id || getClientIP(req);
  const result = rateLimiter.check(`deposit:${userId}`, 3, 10 * 60 * 1000);
  if (!result.allowed) {
    res.setHeader('Retry-After', Math.ceil(result.retryAfterMs / 1000).toString());
    return res.status(429).json({ error: 'Too many deposit requests. Please try again in 10 minutes.' });
  }
  next();
};

// ─────────────────────────────────────────────
// Deposit Reverify Rate Limiter — 5 req / 10 min per user
// ─────────────────────────────────────────────
export const reverifyRateLimiter = (req: Request, res: Response, next: NextFunction) => {
  const userId = req.user?.id || getClientIP(req);
  const result = rateLimiter.check(`reverify:${userId}`, 5, 10 * 60 * 1000);
  if (!result.allowed) {
    res.setHeader('Retry-After', Math.ceil(result.retryAfterMs / 1000).toString());
    return res.status(429).json({ error: 'Too many reverify requests. Please try again in 10 minutes.' });
  }
  next();
};

// ─────────────────────────────────────────────
// Active Subscription Check
// ─────────────────────────────────────────────
export const requireActiveSubscription = async (req: Request, res: Response, next: NextFunction) => {
  const userId = req.user?.id || req.apiKeyUser?.id;
  if (!userId) return res.status(401).json({ error: 'Unauthorized' });

  const isActive = await checkAndAutoRenewSubscription(userId);
  if (!isActive) {
    return res.status(403).json({
      error: 'SUBSCRIPTION_EXPIRED',
      message: 'Your subscription has expired. Please renew.',
    });
  }
  next();
};

// ─────────────────────────────────────────────
// API Key Authentication
// ─────────────────────────────────────────────
export const authenticateApiKey = async (req: Request, res: Response, next: NextFunction) => {
  const authHeader = req.headers['authorization'];
  const xApiKey = req.headers['x-api-key'] as string;

  let token: string | null = null;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    token = authHeader.split(' ')[1];
  } else if (xApiKey) {
    token = xApiKey;
  }

  if (!token) {
    res.status(401).json({ error: 'MISSING_API_KEY', message: 'API key is missing' });
    return;
  }

  // Enforce reasonable key length to avoid DoS via huge keys
  if (token.length > 256) {
    res.status(401).json({ error: 'INVALID_API_KEY', message: 'API key is invalid' });
    return;
  }

  const keyHash = crypto.createHash('sha256').update(token).digest('hex');

  const { data, error } = await supabase
    .from('api_keys')
    .select('user_id')
    .eq('key_hash', keyHash)
    .single();

  if (error || !data) {
    res.status(401).json({ error: 'INVALID_API_KEY', message: 'API key is invalid' });
    return;
  }

  const isActive = await checkAndAutoRenewSubscription(data.user_id);
  if (!isActive) {
    res.status(403).json({ error: 'SUBSCRIPTION_EXPIRED', message: 'Your subscription has expired. Please renew.' });
    return;
  }

  req.apiKeyUser = { id: data.user_id };

  // Fire-and-forget last_used update (non-blocking)
  supabase.from('api_keys').update({ last_used_at: new Date() }).eq('key_hash', keyHash).then();

  next();
};
