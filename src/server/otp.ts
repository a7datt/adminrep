import crypto from 'crypto';
import { supabase } from './db.js';

const RESEND_API_KEY = process.env.RESEND_API_KEY;
const FROM_EMAIL = process.env.FROM_EMAIL || 'syp-api@vipro.sy';

// توليد رمز OTP عشوائي مكون من 6 أرقام
export function generateOTP(): string {
  return crypto.randomInt(100000, 999999).toString();
}

// [CRIT-1 FIX] Hash OTP codes before storing in DB.
// If the database is breached, raw codes cannot be extracted.
// HMAC-SHA256 is used so the secret key adds an extra layer beyond a
// plain SHA-256 hash.  The key is the same SESSION_ENCRYPTION_KEY already
// required at startup, avoiding a new env var.
const OTP_HASH_SECRET = process.env.SESSION_ENCRYPTION_KEY || '';

function hashOTP(email: string, code: string, type: string): string {
  // Bind hash to (email, type) so the same code for a different purpose
  // produces a different hash, preventing cross-context replay.
  return crypto
    .createHmac('sha256', OTP_HASH_SECRET)
    .update(`${email}:${type}:${code}`)
    .digest('hex');
}

// حفظ رمز OTP في قاعدة البيانات
export async function saveOTP(
  email: string,
  code: string,
  type: 'register' | 'login'
): Promise<void> {
  // إبطال الرموز القديمة من نفس النوع لنفس البريد
  await supabase
    .from('otp_codes')
    .update({ used: true })
    .eq('email', email)
    .eq('type', type)
    .eq('used', false);

  const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 دقائق

  // [CRIT-1 FIX] Store only the HMAC hash, never the raw OTP code.
  const codeHash = hashOTP(email, code, type);

  const { error } = await supabase.from('otp_codes').insert({
    email,
    code: codeHash,   // store hash, not plaintext
    type,
    expires_at: expiresAt.toISOString(),
  });

  if (error) throw new Error('Failed to save OTP');
}

// التحقق من رمز OTP
export async function verifyOTP(
  email: string,
  code: string,
  type: 'register' | 'login'
): Promise<boolean> {
  // [CRIT-1 FIX] Hash the candidate code and compare against stored hash.
  const codeHash = hashOTP(email, code, type);

  const { data, error } = await supabase
    .from('otp_codes')
    .select('id, expires_at, used')
    .eq('email', email)
    .eq('code', codeHash)   // compare against hash
    .eq('type', type)
    .eq('used', false)
    .order('created_at', { ascending: false })
    .limit(1)
    .single();

  if (error || !data) return false;
  if (data.used) return false;
  if (new Date(data.expires_at) < new Date()) return false;

  // تعليم الرمز كمستخدم
  await supabase
    .from('otp_codes')
    .update({ used: true })
    .eq('id', data.id);

  return true;
}

// إرسال بريد OTP عبر Resend
export async function sendOTPEmail(
  email: string,
  code: string,
  type: 'register' | 'login'
): Promise<void> {
  const subject =
    type === 'register'
      ? 'رمز التحقق لإنشاء حسابك'
      : 'رمز التحقق لتسجيل الدخول';

  const actionText =
    type === 'register' ? 'إنشاء حسابك الجديد' : 'تسجيل الدخول إلى حسابك';

  const html = `
<!DOCTYPE html>
<html dir="rtl" lang="ar">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${subject}</title>
</head>
<body style="margin:0;padding:0;background-color:#f4f6fb;font-family:Arial,sans-serif;direction:rtl;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background-color:#f4f6fb;padding:40px 0;">
    <tr>
      <td align="center">
        <table width="500" cellpadding="0" cellspacing="0" style="background:#ffffff;border-radius:16px;overflow:hidden;box-shadow:0 4px 20px rgba(9,54,173,0.1);">
          <!-- Header -->
          <tr>
            <td style="background:linear-gradient(135deg,#0936AD,#1a4fd4);padding:32px;text-align:center;">
              <h1 style="color:#ffffff;margin:0;font-size:24px;font-weight:bold;">&#128274; رمز التحقق</h1>
              <p style="color:rgba(255,255,255,0.85);margin:8px 0 0;font-size:14px;">${actionText}</p>
            </td>
          </tr>
          <!-- Body -->
          <tr>
            <td style="padding:40px 32px;">
              <p style="color:#374151;font-size:16px;margin:0 0 24px;line-height:1.6;">
                مرحباً،<br>
                استخدم الرمز أدناه لإتمام عملية <strong>${actionText}</strong>.
              </p>

              <!-- OTP Code Box -->
              <div style="background:#f0f4ff;border:2px dashed #0936AD;border-radius:12px;padding:24px;text-align:center;margin:24px 0;">
                <p style="color:#6b7280;font-size:13px;margin:0 0 8px;">رمز التحقق الخاص بك</p>
                <span style="font-size:42px;font-weight:bold;color:#0936AD;letter-spacing:12px;font-family:monospace;">${code}</span>
              </div>

              <p style="color:#6b7280;font-size:13px;margin:16px 0 0;line-height:1.6;">
                &#9200; صالح لمدة <strong>10 دقائق</strong> فقط.<br>
                &#128274; لا تشارك هذا الرمز مع أي شخص.<br>
                إذا لم تطلب هذا الرمز، يمكنك تجاهل هذا البريد.
              </p>
            </td>
          </tr>
          <!-- Footer -->
          <tr>
            <td style="background:#f9fafb;padding:20px 32px;border-top:1px solid #e5e7eb;text-align:center;">
              <p style="color:#9ca3af;font-size:12px;margin:0;">
                &copy; ${new Date().getFullYear()} SYP API - جميع الحقوق محفوظة
              </p>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>
  `;

  if (!RESEND_API_KEY) {
    console.error('[OTP] RESEND_API_KEY not set');
    throw new Error('Email service not configured');
  }

  const response = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${RESEND_API_KEY}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      from: FROM_EMAIL,
      to: [email],
      subject,
      html,
    }),
  });

  if (!response.ok) {
    const err = await response.text();
    console.error('[OTP Email Error]', err);
    throw new Error('Failed to send OTP email');
  }
}
