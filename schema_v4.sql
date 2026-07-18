-- ═══════════════════════════════════════════════════════════════
-- الحوكمة المتقدّمة (v4) — لجنة متابعة المخالفات، جامعة الطائف
--
-- يضيف هذا التحديث:
--   • نظام صلاحيات RBAC كامل (٩ أدوار) قائم على القدرات (capabilities).
--   • سجل الإصدارات: لقطة لكل تعديل مع إمكانية المقارنة (Diff).
--   • سير موافقات التعديل: طلب تعديل ← موافقة رئيس اللجنة/الحوكمة.
--
-- التشغيل: Supabase → SQL Editor → New query → الصق → Run
-- (يعتمد على schema.sql + v2 + v3 — آمن للتشغيل مرة واحدة، ومتوافق رجعياً)
-- ═══════════════════════════════════════════════════════════════

-- ─── توسيع الأدوار المسموحة ──────────────────────────────────────
alter table members drop constraint if exists members_role_check;
alter table members add constraint members_role_check check (role in (
  'both','committee','recorder',                         -- أدوار قديمة (توافق رجعي)
  'super','governance','chair','supervisor',             -- أدوار جديدة
  'investigator','data_entry','readonly','auditor'
));

-- ─── مصفوفة القدرات لكل دور ──────────────────────────────────────
create or replace function _caps(p_role text) returns jsonb language sql immutable as $$
  select case p_role
    when 'both'         then '{"submit":true,"view":true,"act":true,"archive":true,"restore":true,"edit_locked":true,"manage_members":true,"view_audit":true,"approve_edit":true,"request_edit":true,"export":true}'::jsonb
    when 'super'        then '{"submit":true,"view":true,"act":true,"archive":true,"restore":true,"edit_locked":true,"manage_members":true,"view_audit":true,"approve_edit":true,"request_edit":true,"export":true}'::jsonb
    when 'governance'   then '{"view":true,"act":true,"archive":true,"restore":true,"edit_locked":true,"view_audit":true,"approve_edit":true,"export":true}'::jsonb
    when 'chair'        then '{"view":true,"act":true,"view_audit":true,"approve_edit":true,"export":true}'::jsonb
    when 'committee'    then '{"view":true,"act":true,"request_edit":true,"export":true}'::jsonb
    when 'supervisor'   then '{"view":true,"export":true}'::jsonb
    when 'investigator' then '{"submit":true,"view":true}'::jsonb
    when 'recorder'     then '{"submit":true}'::jsonb
    when 'data_entry'   then '{"submit":true}'::jsonb
    when 'readonly'     then '{"view":true}'::jsonb
    when 'auditor'      then '{"view":true,"view_audit":true,"export":true}'::jsonb
    else '{}'::jsonb end;
$$;

create or replace function _can(p_role text, p_cap text) returns boolean language sql immutable as $$
  select coalesce((_caps(p_role) ->> p_cap)::boolean, false);
$$;

-- ─── الدخول يعيد القدرات ────────────────────────────────────────
create or replace function app_login(p_username text, p_password text)
returns json language plpgsql security definer as $$
declare m members; t uuid;
begin
  select * into m from members where username = p_username;
  if m.id is null then return json_build_object('ok', false, 'error', 'invalid'); end if;
  if m.locked_until is not null and m.locked_until > now() then
    return json_build_object('ok', false, 'error', 'locked', 'until', m.locked_until);
  end if;
  if m.password_hash <> crypt(p_password, m.password_hash) then
    update members set failed_attempts = coalesce(failed_attempts,0)+1,
      locked_until = case when coalesce(failed_attempts,0)+1 >= 5 then now() + interval '15 minutes' else locked_until end
      where id = m.id;
    return json_build_object('ok', false, 'error', 'invalid');
  end if;
  update members set failed_attempts = 0, locked_until = null where id = m.id;
  insert into sessions(member_id) values (m.id) returning token into t;
  perform _audit2(m.display_name, m.username, m.role, 'login', null, null, 'تسجيل دخول', null, null);
  return json_build_object('ok', true, 'token', t, 'display_name', m.display_name,
    'role', m.role, 'username', m.username, 'caps', _caps(m.role));
end; $$;

-- ─── جدول سجل الإصدارات ─────────────────────────────────────────
create table if not exists report_versions (
  id           bigserial primary key,
  report_id    text,
  version_no   int,
  snapshot     jsonb,
  change_type  text,
  changed_by   text,
  changed_role text,
  changed_at   timestamptz default now()
);
create index if not exists rv_report_idx on report_versions(report_id, version_no);
alter table report_versions enable row level security;

create or replace function _snapshot(p_report_id text, p_change_type text, p_by text, p_role text)
returns void language plpgsql security definer as $$
declare v int; r reports;
begin
  select * into r from reports where id = p_report_id;
  if r.id is null then return; end if;
  select coalesce(max(version_no),0)+1 into v from report_versions where report_id = p_report_id;
  insert into report_versions(report_id, version_no, snapshot, change_type, changed_by, changed_role)
  values (p_report_id, v, to_jsonb(r), p_change_type, p_by, p_role);
end; $$;

-- ─── جدول طلبات التعديل ─────────────────────────────────────────
create table if not exists edit_requests (
  id           bigserial primary key,
  report_id    text,
  student_name text,
  proposed     jsonb,
  reason       text,
  status       text default 'pending',   -- pending / approved / rejected
  requested_by text,
  requested_at timestamptz default now(),
  decided_by   text,
  decided_at   timestamptz
);
create index if not exists er_status_idx on edit_requests(status, requested_at desc);
alter table edit_requests enable row level security;

-- ─── تسجيل مخالفة (قدرة submit) + إصدار أوّلي ────────────────────
create or replace function app_submit_report(p_token uuid, p_report jsonb)
returns json language plpgsql security definer as $$
declare m members;
begin
  select * into m from _member_from_token(p_token);
  if m.id is null or not _can(m.role,'submit') then
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
  perform _audit2(m.display_name, m.username, m.role, 'submit', p_report->>'id', p_report->>'studentName', 'تسجيل بلاغ جديد', null, null);
  perform _snapshot(p_report->>'id', 'submit', m.display_name, m.role);
  return json_build_object('ok', true);
end; $$;

-- ─── التحديث الداخلي (يُستخدم مباشرةً أو عبر الموافقة) ────────────
create or replace function _apply_update(p_id text, p_status text, p_committee_notes text,
  p_action_type text, p_action_date text, p_action_by text, p_by text, p_role text)
returns void language plpgsql security definer as $$
declare ex reports;
begin
  select * into ex from reports where id = p_id;
  update reports set status = p_status, committee_notes = p_committee_notes,
    action_type = p_action_type, action_date = p_action_date, action_by = p_action_by
  where id = p_id;
  perform _audit2(p_by, p_by, p_role,
    case when p_status='تم اتخاذ إجراء' and coalesce(ex.action_type,'')='' then 'action_taken'
         when p_status='تم اتخاذ إجراء' and coalesce(ex.action_type,'')<>'' then 'action_edited'
         when ex.status <> p_status then 'status_change' else 'update' end,
    p_id, ex.student_name,
    case when p_status='تم اتخاذ إجراء' then 'إجراء: '||coalesce(p_action_type,'-')
         else 'الحالة: '||coalesce(ex.status,'')||' ← '||coalesce(p_status,'') end, null, null);
  perform _snapshot(p_id, 'update', p_by, p_role);
end; $$;

-- ─── تحديث بلاغ (قدرة act؛ المقفل يحتاج edit_locked) ─────────────
create or replace function app_update_report(
  p_token uuid, p_id text, p_status text, p_committee_notes text,
  p_action_type text, p_action_date text, p_action_by text)
returns json language plpgsql security definer as $$
declare m members; ex reports; locked boolean;
begin
  select * into m from _member_from_token(p_token);
  if m.id is null or not _can(m.role,'act') then
    return json_build_object('ok', false, 'error', 'unauthorized');
  end if;
  select * into ex from reports where id = p_id and coalesce(is_deleted,false) = false;
  if ex.id is null then return json_build_object('ok', false, 'error', 'not_found'); end if;
  locked := (coalesce(ex.action_type,'') <> '' or ex.status = 'إغلاق دون إجراء');
  if locked and not _can(m.role,'edit_locked') then
    return json_build_object('ok', false, 'error', 'action_locked');
  end if;
  perform _apply_update(p_id, p_status, p_committee_notes, p_action_type, p_action_date, p_action_by, m.display_name, m.role);
  return json_build_object('ok', true);
end; $$;

-- ─── الأرشفة (قدرة archive) ─────────────────────────────────────
drop function if exists app_delete_report(uuid, text);
create or replace function app_delete_report(p_token uuid, p_id text, p_reason text)
returns json language plpgsql security definer as $$
declare m members; ex reports;
begin
  select * into m from _member_from_token(p_token);
  if m.id is null or not _can(m.role,'archive') then
    return json_build_object('ok', false, 'error', 'unauthorized');
  end if;
  if coalesce(trim(p_reason),'') = '' then return json_build_object('ok', false, 'error', 'reason_required'); end if;
  select * into ex from reports where id = p_id and coalesce(is_deleted,false) = false;
  if ex.id is null then return json_build_object('ok', false, 'error', 'not_found'); end if;
  update reports set is_deleted = true, deleted_at = now(), deleted_by = m.display_name, delete_reason = p_reason where id = p_id;
  perform _audit2(m.display_name, m.username, m.role, 'delete', p_id, ex.student_name, 'أرشفة بلاغ ('||coalesce(ex.status,'')||')', p_reason, null);
  perform _snapshot(p_id, 'archive', m.display_name, m.role);
  return json_build_object('ok', true);
end; $$;

-- ─── الاستعادة (قدرة restore) ───────────────────────────────────
create or replace function app_restore_report(p_token uuid, p_id text)
returns json language plpgsql security definer as $$
declare m members; ex reports;
begin
  select * into m from _member_from_token(p_token);
  if m.id is null or not _can(m.role,'restore') then return json_build_object('ok', false, 'error', 'unauthorized'); end if;
  select * into ex from reports where id = p_id and coalesce(is_deleted,false) = true;
  if ex.id is null then return json_build_object('ok', false, 'error', 'not_found'); end if;
  update reports set is_deleted = false, deleted_at = null, deleted_by = null, delete_reason = null where id = p_id;
  perform _audit2(m.display_name, m.username, m.role, 'restore', p_id, ex.student_name, 'استعادة بلاغ من الأرشيف', null, null);
  perform _snapshot(p_id, 'restore', m.display_name, m.role);
  return json_build_object('ok', true);
end; $$;

-- ─── القوائم (قدرة view / restore / view_audit / manage_members) ─
create or replace function app_list_reports(p_token uuid)
returns setof reports language plpgsql security definer as $$
declare m members;
begin
  select * into m from _member_from_token(p_token);
  if m.id is null or not _can(m.role,'view') then return; end if;
  return query select * from reports where coalesce(is_deleted,false) = false order by created_at desc;
end; $$;

create or replace function app_list_archive(p_token uuid)
returns setof reports language plpgsql security definer as $$
declare m members;
begin
  select * into m from _member_from_token(p_token);
  if m.id is null or not _can(m.role,'restore') then return; end if;
  return query select * from reports where coalesce(is_deleted,false) = true order by deleted_at desc;
end; $$;

create or replace function app_list_members(p_token uuid)
returns table(username text, display_name text, role text) language plpgsql security definer as $$
declare m members;
begin
  select * into m from _member_from_token(p_token);
  if m.id is null or not _can(m.role,'manage_members') then return; end if;
  return query select mm.username, mm.display_name, mm.role from members mm order by mm.display_name;
end; $$;

create or replace function app_list_audit(p_token uuid)
returns setof audit_log language plpgsql security definer as $$
declare m members;
begin
  select * into m from _member_from_token(p_token);
  if m.id is null or not _can(m.role,'view_audit') then return; end if;
  return query select * from audit_log order by ts desc limit 500;
end; $$;

-- ─── سجل الإصدارات (قدرة view) ──────────────────────────────────
create or replace function app_list_versions(p_token uuid, p_report_id text)
returns setof report_versions language plpgsql security definer as $$
declare m members;
begin
  select * into m from _member_from_token(p_token);
  if m.id is null or not _can(m.role,'view') then return; end if;
  return query select * from report_versions where report_id = p_report_id order by version_no asc;
end; $$;

-- ─── طلب تعديل (قدرة request_edit) ──────────────────────────────
create or replace function app_request_edit(p_token uuid, p_id text, p_proposed jsonb, p_reason text)
returns json language plpgsql security definer as $$
declare m members; ex reports;
begin
  select * into m from _member_from_token(p_token);
  if m.id is null or not _can(m.role,'request_edit') then return json_build_object('ok', false, 'error', 'unauthorized'); end if;
  if coalesce(trim(p_reason),'') = '' then return json_build_object('ok', false, 'error', 'reason_required'); end if;
  select * into ex from reports where id = p_id and coalesce(is_deleted,false)=false;
  if ex.id is null then return json_build_object('ok', false, 'error', 'not_found'); end if;
  insert into edit_requests(report_id, student_name, proposed, reason, requested_by)
  values (p_id, ex.student_name, p_proposed, p_reason, m.display_name);
  perform _audit2(m.display_name, m.username, m.role, 'status_change', p_id, ex.student_name, 'طلب تعديل على إجراء معتمد', p_reason, null);
  return json_build_object('ok', true);
end; $$;

-- ─── قائمة طلبات التعديل (قدرة approve_edit) ────────────────────
create or replace function app_list_edit_requests(p_token uuid)
returns setof edit_requests language plpgsql security definer as $$
declare m members;
begin
  select * into m from _member_from_token(p_token);
  if m.id is null or not _can(m.role,'approve_edit') then return; end if;
  return query select * from edit_requests order by (status='pending') desc, requested_at desc limit 200;
end; $$;

-- ─── البتّ في طلب تعديل (قدرة approve_edit) ─────────────────────
create or replace function app_decide_edit(p_token uuid, p_request_id bigint, p_approve boolean)
returns json language plpgsql security definer as $$
declare m members; er edit_requests; pr jsonb;
begin
  select * into m from _member_from_token(p_token);
  if m.id is null or not _can(m.role,'approve_edit') then return json_build_object('ok', false, 'error', 'unauthorized'); end if;
  select * into er from edit_requests where id = p_request_id and status = 'pending';
  if er.id is null then return json_build_object('ok', false, 'error', 'not_found'); end if;
  if p_approve then
    pr := er.proposed;
    perform _apply_update(er.report_id,
      pr->>'status', pr->>'committeeNotes', pr->>'actionType', pr->>'actionDate', pr->>'actionBy',
      m.display_name, m.role);
    update edit_requests set status='approved', decided_by=m.display_name, decided_at=now() where id=p_request_id;
    perform _audit2(m.display_name, m.username, m.role, 'action_edited', er.report_id, er.student_name, 'اعتماد طلب تعديل', er.reason, null);
  else
    update edit_requests set status='rejected', decided_by=m.display_name, decided_at=now() where id=p_request_id;
    perform _audit2(m.display_name, m.username, m.role, 'status_change', er.report_id, er.student_name, 'رفض طلب تعديل', er.reason, null);
  end if;
  return json_build_object('ok', true);
end; $$;

-- ─── الصلاحيات ──────────────────────────────────────────────────
grant execute on function app_login(text,text)                                  to anon;
grant execute on function app_submit_report(uuid,jsonb)                         to anon;
grant execute on function app_update_report(uuid,text,text,text,text,text,text) to anon;
grant execute on function app_delete_report(uuid,text,text)                     to anon;
grant execute on function app_restore_report(uuid,text)                         to anon;
grant execute on function app_list_reports(uuid)                                to anon;
grant execute on function app_list_archive(uuid)                                to anon;
grant execute on function app_list_members(uuid)                                to anon;
grant execute on function app_list_audit(uuid)                                  to anon;
grant execute on function app_list_versions(uuid,text)                          to anon;
grant execute on function app_request_edit(uuid,text,jsonb,text)                to anon;
grant execute on function app_list_edit_requests(uuid)                          to anon;
grant execute on function app_decide_edit(uuid,bigint,boolean)                  to anon;

-- تم ✓
