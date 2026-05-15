import cron from 'node-cron';
import { supabase } from './db.js';

export function setupCronJobs() {
  // ─── Subscription renewal — every hour ───────
  cron.schedule('0 * * * *', async () => {
    console.log('[Cron] Checking for subscription renewals...');
    try {
      const { data: subs, error: subsErr } = await supabase
        .from('subscriptions')
        .select('id, user_id, auto_renew, expires_at, current_balance, max_wallets')
        .eq('status', 'active');

      if (subsErr) throw subsErr;

      let renewed = 0;
      let expired = 0;
      const now = new Date();

      for (const sub of subs || []) {
        const expiresAt = new Date(sub.expires_at);
        if (expiresAt < now) {
          if (sub.auto_renew) {
            const cost = sub.max_wallets * 0.50;
            if (sub.current_balance >= cost) {
              const newBal = Number(sub.current_balance) - cost;
              const newExpires = new Date();
              newExpires.setMonth(newExpires.getMonth() + 1);

              await supabase.from('subscriptions').update({
                current_balance: newBal,
                expires_at: newExpires.toISOString(),
              }).eq('id', sub.id);
              renewed++;
            } else {
              await supabase.from('subscriptions')
                .update({ status: 'expired', auto_renew: false })
                .eq('id', sub.id);
              expired++;
            }
          } else {
            await supabase.from('subscriptions')
              .update({ status: 'expired' })
              .eq('id', sub.id);
            expired++;
          }
        }
      }

      console.log(`[Cron] Renewal complete. Renewed: ${renewed}, Expired: ${expired}`);
    } catch (error: any) {
      console.error('[Cron] Error checking renewals:', error.message);
    }
  });

  // ─── Cleanup expired OTP codes — every hour ──
  // SECURITY: Prevent unbounded growth of the otp_codes table
  cron.schedule('30 * * * *', async () => {
    try {
      const cutoff = new Date(Date.now() - 60 * 60 * 1000).toISOString(); // older than 1 hour
      const { error } = await supabase
        .from('otp_codes')
        .delete()
        .lt('expires_at', cutoff);

      if (error) console.error('[Cron] OTP cleanup error:', error.message);
      else console.log('[Cron] Expired OTP codes cleaned up');
    } catch (e: any) {
      console.error('[Cron] OTP cleanup failed:', e.message);
    }
  });

  // ─── Cleanup expired/revoked refresh tokens — every 6 hours ──
  // SECURITY: Prevent refresh_tokens table from growing unboundedly
  cron.schedule('0 */6 * * *', async () => {
    try {
      const cutoff = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
      await supabase
        .from('refresh_tokens')
        .delete()
        .or(`revoked.eq.true,expires_at.lt.${cutoff}`);

      console.log('[Cron] Expired refresh tokens cleaned up');
    } catch (e: any) {
      console.error('[Cron] Refresh token cleanup failed:', e.message);
    }
  });
}
