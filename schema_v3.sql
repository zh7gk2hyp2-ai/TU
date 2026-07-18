-- ═══════════════════════════════════════════════════════════════
-- الحوكمة والأمن (v3) — لجنة متابعة المخالفات، جامعة الطائف
--
-- يضيف هذا التحديث:
--   • الأرشفة المنطقية (Soft Delete) بدل الحذف النهائي + الاستعادة (المشرف فقط).
--   • قفل الحساب بعد ٥ محاولات دخول فاشلة (١٥ دقيقة).
--   • توسيع سجل التدقيق: الجهاز/المتصفح، دور المستخدم، وأحداث الدخول/الخروج/الطباعة/التصدير.
--
-- التشغيل: Supabase → SQL Editor → New query → الصق الملف → Run
-- (يعتمد على schema.sql + schema_v2.sql — آمن للتشغيل مرة واحدة)
-- ═══════════════════════════════════════════════════════════════

-- ─── أعمدة جديدة ────────────────────────────────────────────────
alter table audit_log add column if not exists actor_role text;
alter table audit_log add column if not exists device     text;

alter table reports add column if not exists is_deleted    boolean default false;
alter table reports add column if not exists deleted_at    timestamptz;
alter table reports add column if not exists deleted_by    text;
alter table reports add column if not exists delete_reason text;
create index if not exists reports_active_idx on reports(is_deleted);

alter table members add column if not exists failed_attempts int default 0;
alter table members add column if not exists locked_until    timestamptz;

-- ─── دالة تدقيق موسّعة ──────────────────────────────────────────
create or replace function _audit2(p_actor text, p_username text, p_role text, p_event text,
  p_report_id text, p_student text, p_details text, p_reason text, p_device text)
returns void language sql security definer as $$
  insert into audit_log(actor, actor_username, actor_role, event, report_id, student_name, details, reason, device)
  values (p_actor, p_username, p_role, p_event, p_report_id, p_student, p_details, p_reason, p_device);
$$;

-- ─── تسجيل الدخول: قفل بعد المحاولات الفاشلة + توثيق ─────────────
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
    update members set
      failed_attempts = coalesce(failed_attempts,0) + 1,
      locked_until = case when coalesce(failed_attempts,0) + 1 >= 5
                          then now() + interval '15 minutes' else locked_until end
      where id = m.id;
    return json_build_object('ok', false, 'error', 'invalid');
  end if;

  update members set failed_attempts = 0, locked_until = null where id = m.id;
  insert into sessions(member_id) values (m.id) returning token into t;
  perform _audit2(m.display_name, m.username, m.role, 'login', null, null, 'تسجيل دخول', null, null);
  return json_build_object('ok', true, 'token', t,
    'display_name', m.display_name, 'role', m.role, 'username', m.username);
end; $$;

-- ─── تسجيل مخالفة (توثيق موسّع) ─────────────────────────────────
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
  perform _audit2(m.display_name, m.username, m.role, 'submit', p_report->>'id', p_report->>'studentName', 'تسجيل بلاغ جديد', null, null);
  return json_build_object('ok', true);
end; $$;

-- ─── تحديث بلاغ (حماية البلاغات المعتمدة/المُجرى فيها إجراء) ──────
create or replace function app_update_report(
  p_token uuid, p_id text, p_status text, p_committee_notes text,
  p_action_type text, p_action_date text, p_action_by text)
returns json language plpgsql security definer as $$
declare m members; ex reports;
begin
  select * into m from _member_from_token(p_token);
  if m.id is null or m.role not in ('committee','both') then
    return json_build_object('ok', false, 'error', 'unauthorized');
  end if;
  select * into ex from reports where id = p_id and coalesce(is_deleted,false) = false;
  if ex.id is null then return json_build_object('ok', false, 'error', 'not_found'); end if;

  -- حماية مشدّدة: البلاغ المُجرى فيه إجراء أو المغلق لا يعدّله إلا المشرف
  if (coalesce(ex.action_type,'') <> '' or ex.status = 'إغلاق دون إجراء') and m.role <> 'both' then
    return json_build_object('ok', false, 'error', 'action_locked');
  end if;

  update reports set status = p_status, committee_notes = p_committee_notes,
    action_type = p_action_type, action_date = p_action_date, action_by = p_action_by
  where id = p_id;

  perform _audit2(m.display_name, m.username, m.role,
    case
      when p_status = 'تم اتخاذ إجراء' and coalesce(ex.action_type,'') = '' then 'action_taken'
      when p_status = 'تم اتخاذ إجراء' and coalesce(ex.action_type,'') <> '' then 'action_edited'
      when ex.status <> p_status then 'status_change'
      else 'update'
    end,
    p_id, ex.student_name,
    case when p_status = 'تم اتخاذ إجراء' then 'إجراء: ' || coalesce(p_action_type,'-')
         else 'الحالة: ' || coalesce(ex.status,'') || ' ← ' || coalesce(p_status,'') end,
    null, null);
  return json_build_object('ok', true);
end; $$;

-- ─── الأرشفة المنطقية بدل الحذف النهائي (المشرف فقط + سبب) ───────
drop function if exists app_delete_report(uuid, text);
create or replace function app_delete_report(p_token uuid, p_id text, p_reason text)
returns json language plpgsql security definer as $$
declare m members; ex reports;
begin
  select * into m from _member_from_token(p_token);
  if m.id is null or m.role <> 'both' then
    return json_build_object('ok', false, 'error', 'unauthorized');
  end if;
  if coalesce(trim(p_reason),'') = '' then
    return json_build_object('ok', false, 'error', 'reason_required');
  end if;
  select * into ex from reports where id = p_id and coalesce(is_deleted,false) = false;
  if ex.id is null then return json_build_object('ok', false, 'error', 'not_found'); end if;

  update reports set is_deleted = true, deleted_at = now(),
    deleted_by = m.display_name, delete_reason = p_reason where id = p_id;
  perform _audit2(m.display_name, m.username, m.role, 'delete', p_id, ex.student_name,
    'أرشفة بلاغ (' || coalesce(ex.status,'') || ')', p_reason, null);
  return json_build_object('ok', true);
end; $$;

-- ─── عرض البلاغات النشطة فقط (تستبعد المؤرشفة) ───────────────────
create or replace function app_list_reports(p_token uuid)
returns setof reports language plpgsql security definer as $$
declare m members;
begin
  select * into m from _member_from_token(p_token);
  if m.id is null or m.role not in ('committee','both') then return; end if;
  return query select * from reports where coalesce(is_deleted,false) = false order by created_at desc;
end; $$;

-- ─── الأرشيف (المشرف فقط) ───────────────────────────────────────
create or replace function app_list_archive(p_token uuid)
returns setof reports language plpgsql security definer as $$
declare m members;
begin
  select * into m from _member_from_token(p_token);
  if m.id is null or m.role <> 'both' then return; end if;
  return query select * from reports where coalesce(is_deleted,false) = true order by deleted_at desc;
end; $$;

-- ─── استعادة من الأرشيف (المشرف فقط) ────────────────────────────
create or replace function app_restore_report(p_token uuid, p_id text)
returns json language plpgsql security definer as $$
declare m members; ex reports;
begin
  select * into m from _member_from_token(p_token);
  if m.id is null or m.role <> 'both' then return json_build_object('ok', false, 'error', 'unauthorized'); end if;
  select * into ex from reports where id = p_id and coalesce(is_deleted,false) = true;
  if ex.id is null then return json_build_object('ok', false, 'error', 'not_found'); end if;
  update reports set is_deleted = false, deleted_at = null, deleted_by = null, delete_reason = null where id = p_id;
  perform _audit2(m.display_name, m.username, m.role, 'restore', p_id, ex.student_name, 'استعادة بلاغ من الأرشيف', null, null);
  return json_build_object('ok', true);
end; $$;

-- ─── التحقق من كلمة السر (لخطوة تأكيد الأرشفة) بدون إنشاء جلسة ───
create or replace function app_verify_password(p_token uuid, p_password text)
returns json language plpgsql security definer as $$
declare m members;
begin
  select * into m from _member_from_token(p_token);
  if m.id is null then return json_build_object('ok', false); end if;
  return json_build_object('ok', m.password_hash = crypt(p_password, m.password_hash));
end; $$;

-- ─── تسجيل حدث من العميل (خروج/طباعة/تصدير) مع الجهاز ───────────
create or replace function app_log_event(p_token uuid, p_event text, p_details text, p_report_id text, p_device text)
returns json language plpgsql security definer as $$
declare m members;
begin
  select * into m from _member_from_token(p_token);
  if m.id is null then return json_build_object('ok', false); end if;
  if p_event not in ('logout','print','export') then
    return json_build_object('ok', false, 'error', 'bad_event');
  end if;
  perform _audit2(m.display_name, m.username, m.role, p_event, p_report_id, null, coalesce(p_details,''), null, p_device);
  return json_build_object('ok', true);
end; $$;

-- ─── الصلاحيات ──────────────────────────────────────────────────
grant execute on function app_login(text,text)                                  to anon;
grant execute on function app_submit_report(uuid,jsonb)                         to anon;
grant execute on function app_update_report(uuid,text,text,text,text,text,text) to anon;
grant execute on function app_delete_report(uuid,text,text)                     to anon;
grant execute on function app_list_reports(uuid)                                to anon;
grant execute on function app_list_archive(uuid)                                to anon;
grant execute on function app_restore_report(uuid,text)                         to anon;
grant execute on function app_log_event(uuid,text,text,text,text)               to anon;
grant execute on function app_verify_password(uuid,text)                        to anon;

-- تم ✓
