// ═══════════════════════════════════════════════════════════════
// Supabase Edge Function: mfa (سكافولد OTP عبر البريد)
// جامعة الطائف — لجنة متابعة المخالفات
//
// ⚠️ سكافولد: يتطلب مزوّد بريد (هنا Resend) وحقل بريد لكل عضو.
//   يعمل بعد: 1) إضافة عمود email لجدول members  2) ضبط RESEND_API_KEY
//   3) ربط تدفّق دخول من مرحلتين في الواجهة (طلب رمز ← تحقّق).
//
// action=request : يولّد رمزاً من ٦ أرقام، يخزّنه مُجزّأً بصلاحية ٥ دقائق، ويرسله بالبريد.
// action=verify  : يتحقّق من الرمز ويعيد رمز دخول قصير الأجل.
//
// النشر: supabase functions deploy mfa --no-verify-jwt
//        supabase secrets set RESEND_API_KEY=xxx
// ═══════════════════════════════════════════════════════════════
import { serve } from "https://deno.land/std@0.203.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const admin = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!, { auth: { persistSession: false } });
const RESEND_API_KEY = Deno.env.get("RESEND_API_KEY") ?? "";
const SENDER = "no-reply@YOUR-VERIFIED-DOMAIN"; // بدّليه بنطاق مُوثّق في Resend

const CORS: Record<string, string> = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};
const json = (b: unknown, s = 200) => new Response(JSON.stringify(b), { status: s, headers: { ...CORS, "content-type": "application/json" } });

async function sha256(s: string): Promise<string> {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: CORS });
  try {
    const { action, username, code } = await req.json();

    if (action === "request") {
      const { data: m } = await admin.from("members").select("id, email, display_name").eq("username", username).maybeSingle();
      if (!m?.email) return json({ ok: false, error: "no_email" });
      const otp = ("" + Math.floor(100000 + Math.random() * 900000));
      await admin.from("mfa_codes").insert({
        username, code_hash: await sha256(otp), expires_at: new Date(Date.now() + 5 * 60_000).toISOString(),
      });
      // إرسال البريد عبر Resend
      await fetch("https://api.resend.com/emails", {
        method: "POST",
        headers: { "Authorization": `Bearer ${RESEND_API_KEY}`, "content-type": "application/json" },
        body: JSON.stringify({
          from: SENDER, to: m.email, subject: "رمز التحقق — منصة لجنة المخالفات",
          html: `<div dir="rtl" style="font-family:sans-serif">رمز التحقق الخاص بك: <b style="font-size:22px">${otp}</b><br>صالح لمدة ٥ دقائق.</div>`,
        }),
      });
      return json({ ok: true });
    }

    if (action === "verify") {
      const { data: rows } = await admin.from("mfa_codes")
        .select("*").eq("username", username).gt("expires_at", new Date().toISOString())
        .order("id", { ascending: false }).limit(1);
      const row = rows?.[0];
      if (!row || row.code_hash !== await sha256(code)) return json({ ok: false, error: "invalid_code" });
      await admin.from("mfa_codes").delete().eq("id", row.id);
      // هنا تُصدر رمز دخول قصير الأجل / أو تُكمل الدخول عبر app_login_ip
      return json({ ok: true, verified: true });
    }

    return json({ ok: false, error: "bad_action" }, 400);
  } catch (_e) {
    return json({ ok: false, error: "bad_request" }, 400);
  }
});
