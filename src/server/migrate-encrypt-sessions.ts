/**
 * migrate-encrypt-sessions.ts
 *
 * يشغّل هذا السكريبت مرة واحدة فقط بعد النشر لإعادة تشفير
 * أي session_data قديمة غير مشفّرة في قاعدة البيانات.
 *
 * تشغيل:
 *   npx tsx src/server/migrate-encrypt-sessions.ts
 *
 * ⚠️  احتفظ بنسخة احتياطية من قاعدة البيانات قبل التشغيل.
 */

import crypto from 'crypto';
import { createClient } from '@supabase/supabase-js';
import * as dotenv from 'dotenv';
dotenv.config();

// ─── Validate env ───────────────────────────────────────────────────────────
const SUPABASE_URL = process.env.VITE_SUPABASE_URL!;
const SUPABASE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY!;
const SESSION_ENCRYPTION_KEY_HEX = process.env.SESSION_ENCRYPTION_KEY!;

if (!SUPABASE_URL || !SUPABASE_KEY || !SESSION_ENCRYPTION_KEY_HEX) {
  console.error('❌ Missing required env vars: VITE_SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, SESSION_ENCRYPTION_KEY');
  process.exit(1);
}

const SESSION_ENCRYPTION_KEY = Buffer.from(SESSION_ENCRYPTION_KEY_HEX, 'hex');
if (SESSION_ENCRYPTION_KEY.length !== 32) {
  console.error('❌ SESSION_ENCRYPTION_KEY must be exactly 64 hex characters (32 bytes)');
  process.exit(1);
}

const supabase = createClient(SUPABASE_URL, SUPABASE_KEY);

// ─── Encryption helpers (same as shamy.ts) ──────────────────────────────────
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

function isEncrypted(value: any): boolean {
  if (typeof value !== 'string') return false;
  try {
    const parsed = JSON.parse(value);
    return (
      typeof parsed === 'object' &&
      typeof parsed.iv === 'string' &&
      typeof parsed.data === 'string' &&
      typeof parsed.tag === 'string'
    );
  } catch {
    return false;
  }
}

// ─── Migrate a single table ──────────────────────────────────────────────────
async function migrateTable(tableName: string) {
  console.log(`\n🔍 فحص جدول: ${tableName}`);

  const { data: rows, error } = await supabase
    .from(tableName)
    .select('id, session_data')
    .not('session_data', 'is', null);

  if (error) {
    console.error(`  ❌ خطأ في قراءة ${tableName}:`, error.message);
    return;
  }

  if (!rows || rows.length === 0) {
    console.log(`  ✅ لا توجد سجلات — تم`);
    return;
  }

  let encrypted = 0;
  let skipped = 0;
  let failed = 0;

  for (const row of rows) {
    const sessionData = row.session_data;

    // Skip already-encrypted rows
    if (isEncrypted(sessionData)) {
      skipped++;
      continue;
    }

    // session_data is plaintext (object stored as JSONB)
    try {
      const dataToEncrypt = typeof sessionData === 'object' ? sessionData : JSON.parse(sessionData);
      const encryptedValue = encryptSessionData(dataToEncrypt);

      const { error: updateError } = await supabase
        .from(tableName)
        .update({
          session_data: encryptedValue,
          updated_at: new Date().toISOString(),
        })
        .eq('id', row.id);

      if (updateError) {
        console.error(`  ❌ فشل تحديث السجل ${row.id}:`, updateError.message);
        failed++;
      } else {
        encrypted++;
      }
    } catch (err: any) {
      console.error(`  ❌ خطأ في معالجة السجل ${row.id}:`, err.message);
      failed++;
    }
  }

  console.log(`  ✅ مشفَّر: ${encrypted} | تم تخطيه (مشفّر مسبقاً): ${skipped} | فشل: ${failed}`);
}

// ─── Main ────────────────────────────────────────────────────────────────────
async function main() {
  console.log('🚀 بدء migration إعادة تشفير session_data...');
  console.log('⚠️  تأكد من وجود نسخة احتياطية قبل المتابعة!\n');

  await migrateTable('wallets');
  await migrateTable('admin_wallets');

  console.log('\n✅ اكتملت عملية migration بنجاح.');
}

main().catch((err) => {
  console.error('❌ فشلت عملية migration:', err);
  process.exit(1);
});
