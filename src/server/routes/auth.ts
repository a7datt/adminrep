import express from 'express';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { z } from 'zod';
import crypto from 'crypto';
import { supabase } from '../db.js';
import { loginRateLimiter, otpSendRateLimiter, otpEmailRateLimiter, logAuditEvent } from '../middleware.js';
import { generateOTP, saveOTP, verifyOTP, sendOTPEmail } from '../otp.js';

const router = express.Router();

const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) throw new Error('JWT_SECRET environment variable is required');

const JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET;
if (!JWT_REFRESH_SECRET) throw new Error('JWT_REFRESH_SECRET environment variable is required');

const registerSchema = z.object({
  name: z.string().min(2).max(100).trim(),
  email: z.string().email().max(255).toLowerCase().trim(),
  password: z
    .string()
    .min(8, 'Password must be at least 8 characters')
    .max(128)
    .regex(/[A-Z]/, 'Password must contain at least one uppercase letter')
    .regex(/[a-z]/, 'Password must contain at least one lowercase letter')
    .regex(/[0-9]/, 'Password must contain at least one number'),
});

const loginSchema = z.object({
  email: z.string().email().max(255).toLowerCase().trim(),
  password: z.string().min(1).max(128),
});

// ─────────────────────────────────────────────
// Token generation
// SECURITY: Access token is short-lived (15 min) to limit blast radius if stolen.
// Refresh token is 7 days and rotated on each use.
// ─────────────────────────────────────────────
function generateTokens(userId: string, email: string) {
  const accessToken = jwt.sign(
    { id: userId, email },
    JWT_SECRET!,
    { expiresIn: '15m' }  // SHORT-LIVED: was 7d — reduced to 15 minutes
  );
  const refreshToken = jwt.sign(
    { id: userId },
    JWT_REFRESH_SECRET!,
    { expiresIn: '7d' }
  );
  return { accessToken, refreshToken };
}

// Save refresh token hash (never store plain tokens)
async function saveRefreshToken(userId: string, token: string): Promise<void> {
  const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
  const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
  await supabase.from('refresh_tokens').insert({
    user_id: userId,
    token_hash: tokenHash,
    expires_at: expiresAt.toISOString(),
  });
}

// Consume refresh token (one-time use with rotation)
async function consumeRefreshToken(token: string): Promise<string | null> {
  const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
  const { data, error } = await supabase
    .from('refresh_tokens')
    .select('user_id, expires_at, revoked')
    .eq('token_hash', tokenHash)
    .single();

  if (error || !data) return null;
  if (data.revoked) return null;
  if (new Date(data.expires_at) < new Date()) return null;

  // Revoke immediately after consumption (one-time use)
  await supabase
    .from('refresh_tokens')
    .update({ revoked: true, revoked_at: new Date().toISOString() })
    .eq('token_hash', tokenHash);

  return data.user_id;
}

// Revoke all tokens for a user (logout all sessions)
export async function revokeAllUserTokens(userId: string): Promise<void> {
  await supabase
    .from('refresh_tokens')
    .update({ revoked: true, revoked_at: new Date().toISOString() })
    .eq('user_id', userId)
    .eq('revoked', false);
}

// ─────────────────────────────────────────────
// Register Step 1: Send OTP
// SECURITY: otpSendRateLimiter (3/10min per IP) + otpEmailRateLimiter (3/10min per email)
// prevents email spam abuse even when attacker rotates IPs.
// We deliberately return the same success response whether the email exists or not
// to prevent user enumeration.
// ─────────────────────────────────────────────
router.post('/register/send-otp', otpSendRateLimiter, async (req, res) => {
  try {
    const parseResult = registerSchema.safeParse(req.body);
    if (!parseResult.success) {
      res.status(400).json({ error: parseResult.error.errors[0].message });
      return;
    }
    const { email } = parseResult.data;

    // [HIGH-FIX] Per-email rate limit in addition to per-IP limit.
    // Attacker rotating IPs cannot flood a single target email address.
    if (!otpEmailRateLimiter(email)) {
      res.setHeader('Retry-After', '600');
      res.status(429).json({ error: 'Too many OTP requests for this email. Please try again in 10 minutes.' });
      return;
    }

    // Check for existing email — but return the same response to avoid enumeration
    const { data: existingUser } = await supabase
      .from('users')
      .select('id')
      .eq('email', email)
      .single();

    if (existingUser) {
      // Return success-like message to avoid user enumeration
      res.json({ success: true, message: 'OTP sent to your email' });
      return;
    }

    const otp = generateOTP();
    await saveOTP(email, otp, 'register');
    await sendOTPEmail(email, otp, 'register');

    res.json({ success: true, message: 'OTP sent to your email' });
  } catch (error) {
    console.error('[Register Send OTP Error]', (error as Error).message);
    res.status(500).json({ error: 'Failed to send OTP' });
  }
});

// ─────────────────────────────────────────────
// Register Step 2: Verify OTP and create account
// ─────────────────────────────────────────────
router.post('/register', otpSendRateLimiter, async (req, res) => {
  try {
    const parseResult = registerSchema.safeParse(req.body);
    if (!parseResult.success) {
      res.status(400).json({ error: parseResult.error.errors[0].message });
      return;
    }

    const otpCode = req.body.otp_code as string;
    if (!otpCode || !/^\d{6}$/.test(otpCode)) {
      res.status(400).json({ error: 'OTP code is required and must be 6 digits' });
      return;
    }

    const { name, email, password } = parseResult.data;

    const isValidOTP = await verifyOTP(email, otpCode, 'register');
    if (!isValidOTP) {
      res.status(400).json({ error: 'Invalid or expired OTP code' });
      return;
    }

    // Re-check email uniqueness after OTP verification
    const { data: existingUser } = await supabase
      .from('users')
      .select('id')
      .eq('email', email)
      .single();

    if (existingUser) {
      res.status(400).json({ error: 'Email already exists' });
      return;
    }

    const passwordHash = await bcrypt.hash(password, 12);

    const { data: newUser, error: userError } = await supabase
      .from('users')
      .insert({ name, email, password_hash: passwordHash, email_verified: true })
      .select('id, email, name')
      .single();

    if (userError || !newUser) {
      throw userError || new Error('Failed to create user');
    }

    const expiresAt = new Date();
    expiresAt.setHours(expiresAt.getHours() + 24);

    await supabase.from('subscriptions').insert({
      user_id: newUser.id,
      status: 'active',
      max_wallets: 1,
      current_balance: 0,
      expires_at: expiresAt,
    });

    await logAuditEvent(newUser.id, 'USER_REGISTER', { email }, req.ip);

    const { accessToken, refreshToken } = generateTokens(newUser.id, newUser.email);
    await saveRefreshToken(newUser.id, refreshToken);

    // [HIGH-FIX] Set refresh token as HttpOnly, Secure, SameSite=Strict cookie.
    // This prevents JavaScript (including XSS payloads) from reading the refresh token.
    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000,
      path: '/api/auth',
    });

    res.json({
      token: accessToken,
      // refreshToken intentionally omitted from body — it is in the HttpOnly cookie
      user: { id: newUser.id, name: newUser.name, email: newUser.email },
    });
  } catch (error) {
    console.error('[Register Error]', (error as Error).message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ─────────────────────────────────────────────
// Login Step 1: Validate credentials and send OTP
// ─────────────────────────────────────────────
router.post('/login/send-otp', loginRateLimiter, async (req, res) => {
  try {
    const parseResult = loginSchema.safeParse(req.body);
    if (!parseResult.success) {
      res.status(400).json({ error: 'Invalid email or password format' });
      return;
    }
    const { email, password } = parseResult.data;

    // [HIGH-FIX] Per-email rate limit to prevent OTP flooding when IP changes.
    if (!otpEmailRateLimiter(email)) {
      res.setHeader('Retry-After', '600');
      res.status(429).json({ error: 'Too many OTP requests for this email. Please try again in 10 minutes.' });
      return;
    }

    const { data: user, error } = await supabase
      .from('users')
      .select('id, email, name, password_hash, locked_until')
      .eq('email', email)
      .single();

    if (error || !user) {
      // Constant-time comparison to prevent timing attacks
      await bcrypt.compare(password, '$2b$12$invalidhashfortimingnormalization000000000000000000000');
      res.status(401).json({ error: 'Invalid credentials' });
      return;
    }

    if (user.locked_until && new Date(user.locked_until) > new Date()) {
      res.status(423).json({ error: 'Account temporarily locked. Try again later.' });
      return;
    }

    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) {
      await supabase.rpc('increment_failed_login', { user_id: user.id });
      await logAuditEvent(user.id, 'LOGIN_FAILED', { email }, req.ip);
      res.status(401).json({ error: 'Invalid credentials' });
      return;
    }

    const otp = generateOTP();
    await saveOTP(email, otp, 'login');
    await sendOTPEmail(email, otp, 'login');

    res.json({ success: true, message: 'OTP sent to your email' });
  } catch (error) {
    console.error('[Login Send OTP Error]', (error as Error).message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ─────────────────────────────────────────────
// Login Step 2: Verify OTP and issue tokens
// ─────────────────────────────────────────────
router.post('/login', loginRateLimiter, async (req, res) => {
  try {
    const parseResult = loginSchema.safeParse(req.body);
    if (!parseResult.success) {
      res.status(400).json({ error: 'Invalid email or password format' });
      return;
    }

    const otpCode = req.body.otp_code as string;
    if (!otpCode || !/^\d{6}$/.test(otpCode)) {
      res.status(400).json({ error: 'OTP code is required and must be 6 digits' });
      return;
    }

    const { email, password } = parseResult.data;

    const { data: user, error } = await supabase
      .from('users')
      .select('id, email, name, password_hash, locked_until')
      .eq('email', email)
      .single();

    if (error || !user) {
      await bcrypt.compare(password, '$2b$12$invalidhashfortimingnormalization000000000000000000000');
      res.status(401).json({ error: 'Invalid credentials' });
      return;
    }

    if (user.locked_until && new Date(user.locked_until) > new Date()) {
      res.status(423).json({ error: 'Account temporarily locked. Try again later.' });
      return;
    }

    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) {
      await supabase.rpc('increment_failed_login', { user_id: user.id });
      await logAuditEvent(user.id, 'LOGIN_FAILED', { email }, req.ip);
      res.status(401).json({ error: 'Invalid credentials' });
      return;
    }

    const isValidOTP = await verifyOTP(email, otpCode, 'login');
    if (!isValidOTP) {
      res.status(400).json({ error: 'Invalid or expired OTP code' });
      return;
    }

    // Reset failed login counter on success
    await supabase
      .from('users')
      .update({ failed_login_attempts: 0, locked_until: null })
      .eq('id', user.id);

    await logAuditEvent(user.id, 'LOGIN_SUCCESS', { email }, req.ip);

    const { accessToken, refreshToken } = generateTokens(user.id, user.email);
    await saveRefreshToken(user.id, refreshToken);

    // [HIGH-FIX] Refresh token in HttpOnly cookie only — not in response body.
    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000,
      path: '/api/auth',
    });

    res.json({
      token: accessToken,
      // refreshToken intentionally omitted from body
      user: { id: user.id, name: user.name, email: user.email },
    });
  } catch (error) {
    console.error('[Login Error]', (error as Error).message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ─────────────────────────────────────────────
// Token Refresh with full rotation
// SECURITY: Reads refresh token from HttpOnly cookie (primary) or body (legacy fallback).
// Detects token reuse and revokes all sessions if detected.
// ─────────────────────────────────────────────
router.post('/refresh', async (req, res) => {
  // [HIGH-FIX] Prefer HttpOnly cookie over body to prevent XSS-based token theft.
  // Body fallback retained for API clients that don't use cookies.
  const refreshToken = req.cookies?.refreshToken || req.body?.refreshToken;

  if (!refreshToken || typeof refreshToken !== 'string' || refreshToken.length > 512) {
    res.status(401).json({ error: 'Missing or invalid refresh token' });
    return;
  }

  try {
    let payload: { id: string };
    try {
      payload = jwt.verify(refreshToken, JWT_REFRESH_SECRET!) as { id: string };
    } catch {
      res.status(401).json({ error: 'Invalid or expired refresh token' });
      return;
    }

    const userId = await consumeRefreshToken(refreshToken);
    if (!userId || userId !== payload.id) {
      // Token reuse detected — revoke all sessions for this user
      await revokeAllUserTokens(payload.id);
      await logAuditEvent(payload.id, 'REFRESH_TOKEN_REUSE_DETECTED', {}, req.ip);
      res.status(401).json({ error: 'Token reuse detected. All sessions revoked.' });
      return;
    }

    const { data: user, error } = await supabase
      .from('users')
      .select('id, email')
      .eq('id', userId)
      .single();

    if (error || !user) {
      res.status(401).json({ error: 'User not found' });
      return;
    }

    const { accessToken, refreshToken: newRefreshToken } = generateTokens(user.id, user.email);
    await saveRefreshToken(user.id, newRefreshToken);

    // Rotate cookie
    res.cookie('refreshToken', newRefreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000,
      path: '/api/auth',
    });

    res.json({ token: accessToken });
  } catch (err) {
    res.status(401).json({ error: 'Invalid or expired refresh token' });
  }
});

// ─────────────────────────────────────────────
// Logout: Revoke specific refresh token
// ─────────────────────────────────────────────
router.post('/logout', async (req, res) => {
  // Accept token from cookie or body
  const refreshToken = req.cookies?.refreshToken || req.body?.refreshToken;

  if (refreshToken && typeof refreshToken === 'string' && refreshToken.length <= 512) {
    try {
      const tokenHash = crypto.createHash('sha256').update(refreshToken).digest('hex');
      await supabase
        .from('refresh_tokens')
        .update({ revoked: true, revoked_at: new Date().toISOString() })
        .eq('token_hash', tokenHash);
    } catch {
      // Silently ignore logout errors
    }
  }

  // Clear the HttpOnly cookie on logout
  res.clearCookie('refreshToken', {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    path: '/api/auth',
  });

  res.json({ success: true });
});

// ─────────────────────────────────────────────
// Resend OTP
// SECURITY: Rate-limited by both loginRateLimiter, otpSendRateLimiter, and otpEmailRateLimiter.
// ─────────────────────────────────────────────
router.post('/resend-otp', loginRateLimiter, otpSendRateLimiter, async (req, res) => {
  try {
    const schema = z.object({
      email: z.string().email().max(255).toLowerCase().trim(),
      type: z.enum(['register', 'login']),
    });

    const parseResult = schema.safeParse(req.body);
    if (!parseResult.success) {
      res.status(400).json({ error: 'Invalid request' });
      return;
    }

    const { email, type } = parseResult.data;

    // [HIGH-FIX] Per-email rate limit to prevent flooding any single mailbox.
    if (!otpEmailRateLimiter(email)) {
      res.setHeader('Retry-After', '600');
      res.status(429).json({ error: 'Too many OTP requests for this email. Please try again in 10 minutes.' });
      return;
    }

    // For login OTP resend: verify user exists before sending
    if (type === 'login') {
      const { data: user } = await supabase
        .from('users')
        .select('id')
        .eq('email', email)
        .single();

      if (!user) {
        // Return success to avoid user enumeration
        res.json({ success: true, message: 'OTP resent successfully' });
        return;
      }
    }

    const otp = generateOTP();
    await saveOTP(email, otp, type);
    await sendOTPEmail(email, otp, type);

    res.json({ success: true, message: 'OTP resent successfully' });
  } catch (error) {
    console.error('[Resend OTP Error]', (error as Error).message);
    res.status(500).json({ error: 'Failed to resend OTP' });
  }
});

export default router;
