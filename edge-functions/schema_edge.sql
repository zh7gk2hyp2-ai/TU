-- ═══════════════════════════════════════════════════════════════
-- دعم البوابة الآمنة (Edge) — التقاط IP + حدّ محاولات لكل IP
-- جامعة الطائف — لجنة متابعة المخالفات
--
-- التشغيل: Supabase → SQL Editor → Run (بعد v2/v3/v4)
-- تُستدعى app_login_ip حصراً من دالة الحافة (Edge Function) بمفتاح
-- الخدمة service_role — وليست متاحة للعميل (anon) حتى لا يُزوَّر الـ IP.
-- ═══════════════════════════════════════════════════════════════

alter table audit_log add column if not exists ip text;

-- تتبّع محاولات الدخول لكل عنوان IP
create table if not exists ip_login_attempts (
  ip            text primary key,
  attempts      int default 0,
  window_start  timestamptz default now(),
  blocked_until timestamptz
);
alter table ip_login_attempts enable row level security;

-- الدخول مع التقاط IP + حدّ محاولات IP (٢٠ محاولة / ١٠ دقائق) + قفل الحساب
create or replace function app_login_ip(p_username text, p_password text, p_ip text, p_user_agent text)
returns json language plpgsql security definer as $$
declare m members; t uuid; a ip_login_attempts;
begin
  select * into a from ip_login_attempts where ip = p_ip;
  if a.ip is not null and a.blocked_until is not null and a.blocked_until > now() then
    return json_build_object('ok', false, 'error', 'ip_blocked', 'until', a.blocked_until);
  end if;
  if a.ip is null then
    insert into ip_login_attempts(ip) values (p_ip);
    a.attempts := 0;
  elsif a.window_start < now() - interval '10 minutes' then
    update ip_login_attempts set attempts = 0, window_start = now(), blocked_until = null where ip = p_ip;
    a.attempts := 0;
  end if;

  select * into m from members where username = p_username;

  if m.id is null or m.password_hash <> crypt(p_password, coalesce(m.password_hash,'')) then
    if m.id is not null then
      update members set failed_attempts = coalesce(failed_attempts,0)+1,
        locked_until = case when coalesce(failed_attempts,0)+1 >= 5 then now() + interval '15 minutes' else locked_until end
        where id = m.id;
    end if;
    update ip_login_attempts set attempts = attempts + 1,
      blocked_until = case when attempts + 1 >= 20 then now() + interval '15 minutes' else blocked_until end
      where ip = p_ip;
    return json_build_object('ok', false, 'error', 'invalid');
  end if;

  if m.locked_until is not null and m.locked_until > now() then
    return json_build_object('ok', false, 'error', 'locked', 'until', m.locked_until);
  end if;

  update members set failed_attempts = 0, locked_until = null where id = m.id;
  update ip_login_attempts set attempts = 0, blocked_until = null where ip = p_ip;
  insert into sessions(member_id) values (m.id) returning token into t;
  insert into audit_log(actor, actor_username, actor_role, event, details, device, ip)
    values (m.display_name, m.username, m.role, 'login', 'تسجيل دخول', p_user_agent, p_ip);

  return json_build_object('ok', true, 'token', t,
    'display_name', m.display_name, 'role', m.role, 'username', m.username);
end; $$;

-- لا تُمنح لـ anon: يستدعيها الـ Edge Function فقط عبر service_role
revoke execute on function app_login_ip(text,text,text,text) from anon;
revoke execute on function app_login_ip(text,text,text,text) from public;

-- تم ✓
