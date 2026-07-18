-- ═══════════════════════════════════════════════════════════════
-- سكافولد OTP — جداول التحقق الثنائي بالبريد
-- (يُشغَّل فقط إن رغبتِ بتفعيل OTP الحقيقي مع مزوّد بريد)
-- ═══════════════════════════════════════════════════════════════

-- بريد لكل عضو (لإرسال الرمز)
alter table members add column if not exists email text;

-- رموز التحقق المؤقتة (مُجزّأة، بصلاحية قصيرة)
create table if not exists mfa_codes (
  id         bigserial primary key,
  username   text,
  code_hash  text,
  expires_at timestamptz,
  created_at timestamptz default now()
);
create index if not exists mfa_user_idx on mfa_codes(username, expires_at desc);
alter table mfa_codes enable row level security;
-- لا policy: الوصول عبر service_role (Edge Function) فقط.

-- تم ✓
