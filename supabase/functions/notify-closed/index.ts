// notify-closed: sends "Results are in" web pushes for polls that just closed.
// Triggered by a pg_cron job (see supabase/008_push_notifications.sql). Idempotent, so it needs no auth:
// each closed poll is taken exactly once by take_closed_notifications().
import { encrypt, importVapidKey, newVapidKeys, vapidHeader } from "./webpush.js";

const SB_URL = Deno.env.get("SUPABASE_URL")!, SB_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
const SUBJECT = "https://simmigon-flagg.github.io/blind-vote/";
const PUSH_HOSTS = /(^|\.)(push\.apple\.com|googleapis\.com|notify\.windows\.com|push\.services\.mozilla\.com)$/;
const json = (o: unknown, status = 200) => new Response(JSON.stringify(o), { status, headers: { "Content-Type": "application/json" } });

async function rpc(fn: string, args: Record<string, unknown> = {}) {
  const r = await fetch(`${SB_URL}/rest/v1/rpc/${fn}`, {
    method: "POST", headers: { apikey: SB_KEY, Authorization: `Bearer ${SB_KEY}`, "Content-Type": "application/json" }, body: JSON.stringify(args),
  });
  const t = await r.text();
  if (!r.ok) throw new Error(`${fn}: ${r.status} ${t}`);
  return t ? JSON.parse(t) : null;
}

Deno.serve(async () => {
  try {
    // The VAPID key pair is created once, on the first run, and kept in the database.
    let keys = await rpc("push_keys_get");
    if (!keys) keys = await rpc("push_keys_set", await (async () => { const k = await newVapidKeys(); return { p_pub: k.pub, p_priv: k.priv }; })());
    const rows: { poll_id: string; question: string; endpoint: string; p256dh: string; auth: string }[] = (await rpc("take_closed_notifications")) ?? [];
    if (!rows.length) return json({ sent: 0, failed: 0 });
    const signKey = await importVapidKey(keys.priv);
    let sent = 0, failed = 0;
    await Promise.all(rows.map(async r => {
      try {
        if (!PUSH_HOSTS.test(new URL(r.endpoint).hostname)) throw new Error("not a push service");
        const body = await encrypt(r.p256dh, r.auth, JSON.stringify({ title: "Results are in", body: r.question, poll: r.poll_id }));
        const res = await fetch(r.endpoint, {
          method: "POST", body,
          headers: { Authorization: await vapidHeader(r.endpoint, keys.pub, signKey, SUBJECT), "Content-Encoding": "aes128gcm", "Content-Type": "application/octet-stream", TTL: "86400", Urgency: "normal" },
        });
        if (res.ok) { sent++; return; }
        failed++;
        console.log("push failed", res.status, (await res.text()).slice(0, 200));
        if (res.status === 404 || res.status === 410) await rpc("drop_push_sub", { p_endpoint: r.endpoint }); // subscription is gone
      } catch (e) { failed++; console.log("push error", String(e)); }
    }));
    return json({ sent, failed });
  } catch (e) {
    console.log("notify-closed error", String(e));
    return json({ error: String(e) }, 500);
  }
});
