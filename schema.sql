-- ═══════════════════════════════════════════════════════════════
-- لجنة متابعة مخالفات الملبس والمظهر — جامعة الطائف
-- قاعدة بيانات Supabase (مشتركة بين كل الأجهزة)
--
-- التصميم الأمني:
--   • كلمات السر مشفّرة (bcrypt) — لا تُخزّن نصّاً.
--   • الجداول مقفلة تماماً (RLS) — لا يمكن الوصول المباشر لها بمفتاح anon.
--   • كل العمليات تمر عبر دوال آمنة (RPC) تتحقق من الجلسة والصلاحية.
--
-- طريقة التشغيل: انسخي كامل هذا الملف والصقيه في:
--   Supabase → مشروعك → SQL Editor → New query → Run
-- ═══════════════════════════════════════════════════════════════

create extension if not exists pgcrypto;

-- ─── الجداول ────────────────────────────────────────────────────
create table if not exists members (
  id            uuid primary key default gen_random_uuid(),
  username      text unique not null,
  password_hash text not null,
  display_name  text not null,
  role          text not null check (role in ('recorder','committee','both')),
  created_at    timestamptz default now()
);

create table if not exists sessions (
  token      uuid primary key default gen_random_uuid(),
  member_id  uuid references members(id) on delete cascade,
  created_at timestamptz default now(),
  expires_at timestamptz default now() + interval '30 days'
);

create table if not exists reports (
  id                  text primary key,
  created_at          timestamptz default now(),
  student_name        text not null,
  university_id       text not null,
  college             text,
  college_other       text,
  department          text,
  building_gate       text,
  building_gate_other text,
  recorder_name       text,
  violation_types     jsonb default '[]'::jsonb,
  violation_type_other text,
  notes               text,
  status              text default 'جديد',
  committee_notes     text default '',
  action_type         text default '',
  action_date         text default '',
  action_by           text default ''
);

create index if not exists reports_university_id_idx on reports(university_id);
create index if not exists reports_created_idx on reports(created_at desc);

-- ─── قفل الجداول (RLS) — لا وصول مباشر إطلاقاً ─────────────────────
alter table members  enable row level security;
alter table sessions enable row level security;
alter table reports  enable row level security;
-- لا نُنشئ أي policy → PostgREST يرفض كل وصول مباشر عبر مفتاح anon.
-- الوصول الوحيد عبر دوال SECURITY DEFINER أدناه.

-- ─── دالة داخلية: من هو صاحب هذه الجلسة؟ ──────────────────────────
create or replace function _member_from_token(p_token uuid)
returns members language sql security definer stable as $$
  select m.* from members m
  join sessions s on s.member_id = m.id
  where s.token = p_token and s.expires_at > now()
  limit 1;
$$;

-- ─── تسجيل الدخول ───────────────────────────────────────────────
create or replace function app_login(p_username text, p_password text)
returns json language plpgsql security definer as $$
declare m members; t uuid;
begin
  select * into m from members where username = p_username;
  if m.id is null or m.password_hash <> crypt(p_password, m.password_hash) then
    return json_build_object('ok', false);
  end if;
  insert into sessions(member_id) values (m.id) returning token into t;
  return json_build_object('ok', true, 'token', t,
    'display_name', m.display_name, 'role', m.role, 'username', m.username);
end; $$;

create or replace function app_logout(p_token uuid)
returns json language plpgsql security definer as $$
begin
  delete from sessions where token = p_token;
  return json_build_object('ok', true);
end; $$;

-- ─── تسجيل مخالفة (recorder / both) ──────────────────────────────
create or replace function app_submit_report(p_token uuid, p_report jsonb)
returns json language plpgsql security definer as $$
declare m members;
begin
  select * into m from _member_from_token(p_token);
  if m.id is null or m.role not in ('recorder','both') then
    return json_build_object('ok', false, 'error', 'unauthorized');
  end if;
  insert into reports(id, student_name, university_id, college, college_other, department,
    building_gate, building_gate_other, recorder_name, violation_types, violation_type_other, notes)
  values (
    p_report->>'id', p_report->>'studentName', p_report->>'universityId', p_report->>'college',
    p_report->>'collegeOther', p_report->>'department', p_report->>'buildingGate',
    p_report->>'buildingGateOther', coalesce(p_report->>'recorderName', m.display_name),
    coalesce(p_report->'violationTypes','[]'::jsonb), p_report->>'violationTypeOther', p_report->>'notes'
  );
  return json_build_object('ok', true);
end; $$;

-- ─── عرض كل البلاغات (committee / both) ──────────────────────────
create or replace function app_list_reports(p_token uuid)
returns setof reports language plpgsql security definer as $$
declare m members;
begin
  select * into m from _member_from_token(p_token);
  if m.id is null or m.role not in ('committee','both') then return; end if;
  return query select * from reports order by created_at desc;
end; $$;

-- ─── تحديث حالة/إجراء بلاغ (committee / both) ─────────────────────
create or replace function app_update_report(
  p_token uuid, p_id text, p_status text, p_committee_notes text,
  p_action_type text, p_action_date text, p_action_by text)
returns json language plpgsql security definer as $$
declare m members;
begin
  select * into m from _member_from_token(p_token);
  if m.id is null or m.role not in ('committee','both') then
    return json_build_object('ok', false, 'error', 'unauthorized');
  end if;
  update reports set
    status = p_status, committee_notes = p_committee_notes,
    action_type = p_action_type, action_date = p_action_date, action_by = p_action_by
  where id = p_id;
  return json_build_object('ok', true);
end; $$;

-- ─── حذف بلاغ (committee / both) ─────────────────────────────────
create or replace function app_delete_report(p_token uuid, p_id text)
returns json language plpgsql security definer as $$
declare m members;
begin
  select * into m from _member_from_token(p_token);
  if m.id is null or m.role not in ('committee','both') then
    return json_build_object('ok', false, 'error', 'unauthorized');
  end if;
  delete from reports where id = p_id;
  return json_build_object('ok', true);
end; $$;

-- ─── إدارة الأعضاء (admin = دور both فقط) ────────────────────────
create or replace function app_list_members(p_token uuid)
returns table(username text, display_name text, role text)
language plpgsql security definer as $$
declare m members;
begin
  select * into m from _member_from_token(p_token);
  if m.id is null or m.role <> 'both' then return; end if;
  return query select mm.username, mm.display_name, mm.role from members mm order by mm.created_at;
end; $$;

create or replace function app_save_member(
  p_token uuid, p_username text, p_password text, p_display_name text, p_role text)
returns json language plpgsql security definer as $$
declare m members; existing members;
begin
  select * into m from _member_from_token(p_token);
  if m.id is null or m.role <> 'both' then
    return json_build_object('ok', false, 'error', 'unauthorized');
  end if;
  select * into existing from members where username = p_username;
  if existing.id is not null then
    update members set display_name = p_display_name, role = p_role,
      password_hash = case when coalesce(p_password,'') = '' then password_hash
                           else crypt(p_password, gen_salt('bf')) end
    where username = p_username;
  else
    if coalesce(p_password,'') = '' then
      return json_build_object('ok', false, 'error', 'password_required');
    end if;
    insert into members(username, password_hash, display_name, role)
    values (p_username, crypt(p_password, gen_salt('bf')), p_display_name, p_role);
  end if;
  return json_build_object('ok', true);
end; $$;

create or replace function app_delete_member(p_token uuid, p_username text)
returns json language plpgsql security definer as $$
declare m members;
begin
  select * into m from _member_from_token(p_token);
  if m.id is null or m.role <> 'both' then
    return json_build_object('ok', false, 'error', 'unauthorized');
  end if;
  -- لا تحذف نفسك ولا آخر مشرف
  if (select count(*) from members where role = 'both') <= 1
     and exists (select 1 from members where username = p_username and role = 'both') then
    return json_build_object('ok', false, 'error', 'last_admin');
  end if;
  delete from members where username = p_username;
  return json_build_object('ok', true);
end; $$;

-- ─── منح صلاحية استدعاء الدوال لمفتاح anon (العام) ────────────────
grant execute on function app_login(text,text)                     to anon;
grant execute on function app_logout(uuid)                         to anon;
grant execute on function app_submit_report(uuid,jsonb)            to anon;
grant execute on function app_list_reports(uuid)                   to anon;
grant execute on function app_update_report(uuid,text,text,text,text,text,text) to anon;
grant execute on function app_delete_report(uuid,text)             to anon;
grant execute on function app_list_members(uuid)                   to anon;
grant execute on function app_save_member(uuid,text,text,text,text) to anon;
grant execute on function app_delete_member(uuid,text)             to anon;

-- ─── الحسابات الافتراضية (كلمات السر مشفّرة) ──────────────────────
insert into members(username, password_hash, display_name, role) values
  ('admin',    crypt('2580', gen_salt('bf')), 'المشرفة العامة',      'both'),
  ('lajna1',   crypt('1111', gen_salt('bf')), 'عضو اللجنة 1',        'committee'),
  ('lajna2',   crypt('2222', gen_salt('bf')), 'عضو اللجنة 2',        'committee'),
  ('tasjeel1', crypt('3333', gen_salt('bf')), 'مسجّلة المخالفات 1',   'recorder'),
  ('tasjeel2', crypt('4444', gen_salt('bf')), 'مسجّلة المخالفات 2',   'recorder')
on conflict (username) do nothing;

-- تم ✓
