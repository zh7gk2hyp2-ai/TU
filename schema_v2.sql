-- ═══════════════════════════════════════════════════════════════
-- تحديث الصلاحيات وسجل التدقيق — لجنة متابعة المخالفات، جامعة الطائف
--
-- ما الذي يضيفه هذا الملف:
--   • جدول سجل تدقيق (audit_log) يوثّق كل عملية.
--   • حماية مشدّدة: حذف البلاغات وتعديل الإجراءات المسجّلة للمشرف (both) فقط.
--   • الحذف يتطلب سبباً إلزامياً ويُسجَّل في السجل.
--
-- طريقة التشغيل: انسخي كامل هذا الملف في:
--   Supabase → مشروعك → SQL Editor → New query → Run
-- (آمن للتشغيل مرة واحدة — يعتمد على schema.sql الأساسي)
-- ═══════════════════════════════════════════════════════════════

-- ─── جدول سجل التدقيق ───────────────────────────────────────────
create table if not exists audit_log (
  id             bigserial primary key,
  ts             timestamptz default now(),
  actor          text,   -- الاسم الظاهر لمن قام بالعملية
  actor_username text,
  event          text,   -- submit / status_change / action_taken / action_edited / delete
  report_id      text,
  student_name   text,
  details        text,
  reason         text    -- سبب الحذف
);
create index if not exists audit_ts_idx on audit_log(ts desc);
alter table audit_log enable row level security;
-- لا policy → لا وصول مباشر؛ فقط عبر الدوال الآمنة أدناه.

-- ─── دالة تسجيل داخلية ──────────────────────────────────────────
create or replace function _audit(p_actor text, p_username text, p_event text,
  p_report_id text, p_student text, p_details text, p_reason text)
returns void language sql security definer as $$
  insert into audit_log(actor, actor_username, event, report_id, student_name, details, reason)
  values (p_actor, p_username, p_event, p_report_id, p_student, p_details, p_reason);
$$;

-- ─── تسجيل مخالفة (مع توثيق) ────────────────────────────────────
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
  perform _audit(m.display_name, m.username, 'submit', p_report->>'id', p_report->>'studentName', 'تسجيل بلاغ جديد', null);
  return json_build_object('ok', true);
end; $$;

-- ─── تحديث بلاغ (حماية الإجراءات المسجّلة + توثيق) ────────────────
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
  select * into ex from reports where id = p_id;
  if ex.id is null then return json_build_object('ok', false, 'error', 'not_found'); end if;

  -- حماية مشدّدة: البلاغ الذي اتُّخذ فيه إجراء لا يعدّله إلا المشرف
  if coalesce(ex.action_type,'') <> '' and m.role <> 'both' then
    return json_build_object('ok', false, 'error', 'action_locked');
  end if;

  update reports set
    status = p_status, committee_notes = p_committee_notes,
    action_type = p_action_type, action_date = p_action_date, action_by = p_action_by
  where id = p_id;

  perform _audit(m.display_name, m.username,
    case
      when p_status = 'تم اتخاذ إجراء' and coalesce(ex.action_type,'') = '' then 'action_taken'
      when p_status = 'تم اتخاذ إجراء' and coalesce(ex.action_type,'') <> '' then 'action_edited'
      when ex.status <> p_status then 'status_change'
      else 'update'
    end,
    p_id, ex.student_name,
    case when p_status = 'تم اتخاذ إجراء'
         then 'إجراء: ' || coalesce(p_action_type,'-')
         else 'الحالة: ' || coalesce(ex.status,'') || ' ← ' || coalesce(p_status,'') end,
    null);

  return json_build_object('ok', true);
end; $$;

-- ─── حذف بلاغ (المشرف فقط + سبب إلزامي + توثيق) ──────────────────
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
  select * into ex from reports where id = p_id;
  if ex.id is null then return json_build_object('ok', false, 'error', 'not_found'); end if;

  perform _audit(m.display_name, m.username, 'delete', p_id, ex.student_name,
    'حذف بلاغ (' || coalesce(ex.status,'') || ')', p_reason);
  delete from reports where id = p_id;
  return json_build_object('ok', true);
end; $$;

-- ─── عرض سجل التدقيق (المشرف فقط) ────────────────────────────────
create or replace function app_list_audit(p_token uuid)
returns setof audit_log language plpgsql security definer as $$
declare m members;
begin
  select * into m from _member_from_token(p_token);
  if m.id is null or m.role <> 'both' then return; end if;
  return query select * from audit_log order by ts desc limit 500;
end; $$;

-- ─── منح الصلاحيات ──────────────────────────────────────────────
grant execute on function app_submit_report(uuid,jsonb)                          to anon;
grant execute on function app_update_report(uuid,text,text,text,text,text,text)  to anon;
grant execute on function app_delete_report(uuid,text,text)                      to anon;
grant execute on function app_list_audit(uuid)                                   to anon;

-- تم ✓
