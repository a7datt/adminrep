import express from 'express';
import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import { supabase } from '../db.js';
import { logAuditEvent, otpSendRateLimiter } from '../middleware.js';

const router = express.Router();

const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const JWT_SECRET = process.env.JWT_SECRET!;
const JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET!;

if (!GOOGLE_CLIENT_ID || !GOOGLE_CLIENT_SECRET) {
  console.warn('[Google OAuth] GOOGLE_CLIENT_ID or GOOGLE_CLIENT_SECRET not set');
}

function getRedirectUri(req: express.Request) {
  const origin =
    process.env.NODE_ENV === 'production'
      ? `https://${req.headers.host}`
      : `http://localhost:${process.env.PORT || 3000}`;
  return `${origin}/api/auth/google/callback`;
}

// SECURITY: Access token short-lived (15 min), refresh token 7 days with rotation
function generateTokens(userId: string, email: string) {
  const accessToken = jwt.sign({ id: userId, email }, JWT_SECRET, { expiresIn: '15m' });
  const refreshToken = jwt.sign({ id: userId }, JWT_REFRESH_SECRET, { expiresIn: '7d' });
  return { accessToken, refreshToken };
}

async function saveRefreshToken(userId: string, token: string): Promise<void> {
  const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
  const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
  await supabase.from('refresh_tokens').insert({
    user_id: userId,
    token_hash: tokenHash,
    expires_at: expiresAt.toISOString(),
  });
}

// ─── Step 1: Redirect to Google ───────────────
// SECURITY: Rate-limited to prevent CSRF state table spam
router.get('/', otpSendRateLimiter, (req, res) => {
  if (!GOOGLE_CLIENT_ID) {
    res.status(503).json({ error: 'Google OAuth not configured' });
    return;
  }

  const state = crypto.randomBytes(16).toString('hex');

  supabase.from('otp_codes').insert({
    email: `__oauth_state__${state}`,
    code: state,
    type: 'login',
    expires_at: new Date(Date.now() + 10 * 60 * 1000).toISOString(),
  }).then(() => {
    const params = new URLSearchParams({
      client_id: GOOGLE_CLIENT_ID!,
      redirect_uri: getRedirectUri(req),
      response_type: 'code',
      scope: 'openid email profile',
      state,
      access_type: 'offline',
      prompt: 'select_account',
    });
    res.redirect(`https://accounts.google.com/o/oauth2/v2/auth?${params}`);
  }).catch(() => {
    res.status(500).json({ error: 'Internal server error' });
  });
});

// ─── Step 2: Handle Google callback ──────────
router.get('/callback', async (req, res) => {
  const { code, state, error } = req.query as Record<string, string>;

  if (error) {
    res.redirect('/login?error=' + encodeURIComponent('Google login was cancelled'));
    return;
  }

  // SECURITY: Validate that code and state are strings of reasonable length only
  if (!state || typeof state !== 'string' || state.length > 64 ||
      !code  || typeof code  !== 'string' || code.length  > 512) {
    res.redirect('/login?error=' + encodeURIComponent('Invalid request, please try again'));
    return;
  }

  try {
    // SECURITY: Verify CSRF state from DB (one-time use)
    const { data: stateRecord, error: stateErr } = await supabase
      .from('otp_codes')
      .select('id, expires_at, used')
      .eq('email', `__oauth_state__${state}`)
      .eq('code', state)
      .eq('used', false)
      .single();

    if (stateErr || !stateRecord || new Date(stateRecord.expires_at) < new Date()) {
      res.redirect('/login?error=' + encodeURIComponent('Session expired, please try again'));
      return;
    }

    // Mark state as used to prevent replay
    await supabase.from('otp_codes').update({ used: true }).eq('id', stateRecord.id);

    // Exchange authorization code for tokens
    const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        code,
        client_id: GOOGLE_CLIENT_ID!,
        client_secret: GOOGLE_CLIENT_SECRET!,
        redirect_uri: getRedirectUri(req),
        grant_type: 'authorization_code',
      }),
    });

    if (!tokenRes.ok) {
      console.error('[Google OAuth token exchange error]', tokenRes.status);
      res.redirect('/login?error=' + encodeURIComponent('Failed to connect with Google'));
      return;
    }

    const tokenData = await tokenRes.json();
    const idToken: string = tokenData.id_token;

    if (!idToken || typeof idToken !== 'string') {
      res.redirect('/login?error=' + encodeURIComponent('Invalid Google response'));
      return;
    }

    // [CRIT-4 FIX] Verify id_token using Google's userinfo endpoint with the
    // access_token rather than the deprecated tokeninfo endpoint.
    // The tokeninfo endpoint is a convenience endpoint not intended for server-side
    // verification. Using the access_token against userinfo is the correct OAuth2 approach.
    // Additionally we still validate aud to prevent token substitution attacks.
    const accessToken: string = tokenData.access_token;
    if (!accessToken || typeof accessToken !== 'string') {
      res.redirect('/login?error=' + encodeURIComponent('Invalid Google response'));
      return;
    }

    const userInfoRes = await fetch('https://www.googleapis.com/oauth2/v3/userinfo', {
      headers: { Authorization: `Bearer ${accessToken}` },
    });

    if (!userInfoRes.ok) {
      res.redirect('/login?error=' + encodeURIComponent('Failed to verify Google identity'));
      return;
    }

    const googleUser = await userInfoRes.json();

    // [CRIT-4 FIX] Additionally decode the id_token JWT to double-check aud claim.
    // This prevents token substitution where an attacker presents a valid Google token
    // issued for a different application.
    try {
      const [, payloadB64] = idToken.split('.');
      const idTokenPayload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString('utf8'));
      if (idTokenPayload.aud !== GOOGLE_CLIENT_ID) {
        res.redirect('/login?error=' + encodeURIComponent('Invalid Google token'));
        return;
      }
      // Also check issuer to prevent tokens from rogue issuers
      if (!['accounts.google.com', 'https://accounts.google.com'].includes(idTokenPayload.iss)) {
        res.redirect('/login?error=' + encodeURIComponent('Invalid Google token issuer'));
        return;
      }
    } catch {
      res.redirect('/login?error=' + encodeURIComponent('Failed to validate Google token'));
      return;
    }

    const { sub: googleId, email, name, picture } = googleUser as {
      sub: string; email: string; name: string; picture: string;
    };

    if (!email || typeof email !== 'string' || !email.includes('@')) {
      res.redirect('/login?error=' + encodeURIComponent('Could not get email from Google'));
      return;
    }

    // Find or create user
    let userId: string;

    const { data: existingByGoogle } = await supabase
      .from('users').select('id').eq('google_id', googleId).single();

    if (existingByGoogle) {
      userId = existingByGoogle.id;
    } else {
      const { data: existingByEmail } = await supabase
        .from('users').select('id').eq('email', email).single();

      if (existingByEmail) {
        await supabase.from('users')
          .update({ google_id: googleId, avatar_url: picture, email_verified: true })
          .eq('id', existingByEmail.id);
        userId = existingByEmail.id;
      } else {
        const { data: newUser, error: createErr } = await supabase
          .from('users')
          .insert({
            name: name || email.split('@')[0],
            email,
            google_id: googleId,
            avatar_url: picture,
            email_verified: true,
            password_hash: '',
          })
          .select('id')
          .single();

        if (createErr || !newUser) {
          console.error('[Google OAuth create user error]', createErr?.message);
          res.redirect('/login?error=' + encodeURIComponent('Failed to create account'));
          return;
        }

        userId = newUser.id;

        const expiresAt = new Date();
        expiresAt.setHours(expiresAt.getHours() + 24);
        await supabase.from('subscriptions').insert({
          user_id: userId,
          status: 'active',
          max_wallets: 1,
          current_balance: 0,
          expires_at: expiresAt,
        });
      }
    }

    await logAuditEvent(userId, 'LOGIN_GOOGLE', { email }, req.ip);

    const { accessToken: appAccessToken, refreshToken } = generateTokens(userId, email);
    await saveRefreshToken(userId, refreshToken);

    // [HIGH-FIX] Set refresh token as HttpOnly, Secure, SameSite=Strict cookie
    // instead of passing it in the URL where it is visible in server logs,
    // browser history, and Referer headers.
    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days in ms
      path: '/api/auth',
    });

    // Only pass the short-lived access token in the URL payload.
    // The refresh token is now in a cookie, not in the URL.
    const payload = Buffer.from(
      JSON.stringify({ token: appAccessToken, email, name: name || email })
    ).toString('base64');

    res.redirect(`/auth/google/success?data=${encodeURIComponent(payload)}`);
  } catch (err) {
    console.error('[Google OAuth callback error]', (err as Error).message);
    res.redirect('/login?error=' + encodeURIComponent('An error occurred, please try again'));
  }
});

export default router;
