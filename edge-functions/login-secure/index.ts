// ═══════════════════════════════════════════════════════════════
// Supabase Edge Function: login-secure
// جامعة الطائف — لجنة متابعة المخالفات
//
// يلتقط عنوان IP للعميل + معلومات الجهاز/المتصفح، ويطبّق حدّ محاولات
// لكل IP، ثم ينفّذ الدخول عبر دالة قاعدة بيانات آمنة تسجّل الـ IP في
// سجل التدقيق. تُستدعى من الواجهة بدل app_login عند ضبط EDGE_LOGIN_URL.
//
// النشر:
//   supabase functions deploy login-secure --no-verify-jwt
//   (متغيّرات SUPABASE_URL و SUPABASE_SERVICE_ROLE_KEY متوفّرة تلقائياً)
// ═══════════════════════════════════════════════════════════════
import { serve } from "https://deno.land/std@0.203.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const SUPABASE_URL = Deno.env.get("SUPABASE_URL")!;
const SERVICE_ROLE = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
const admin = createClient(SUPABASE_URL, SERVICE_ROLE, { auth: { persistSession: false } });

// اضبطي النطاق المسموح (Origin) بدل * في الإنتاج لتشديد CORS
const CORS: Record<string, string> = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, content-type, apikey",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

function clientIp(req: Request): string {
  const xff = req.headers.get("x-forwarded-for");
  if (xff) return xff.split(",")[0].trim();
  return req.headers.get("x-real-ip") ?? "unknown";
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...CORS, "content-type": "application/json" },
  });
}

serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: CORS });
  if (req.method !== "POST") return json({ ok: false, error: "method" }, 405);

  try {
    const { username, password } = await req.json();
    if (!username || !password) return json({ ok: false, error: "missing" }, 400);

    const ip = clientIp(req);
    const ua = req.headers.get("user-agent") ?? "";

    // الدالة تُطبّق حدّ محاولات الـ IP + قفل الحساب + تسجّل الـ IP في التدقيق
    const { data, error } = await admin.rpc("app_login_ip", {
      p_username: username,
      p_password: password,
      p_ip: ip,
      p_user_agent: ua,
    });

    if (error) {
      console.error("app_login_ip error:", error.message);
      return json({ ok: false, error: "server" });
    }
    return json(data);
  } catch (_e) {
    return json({ ok: false, error: "bad_request" }, 400);
  }
});
