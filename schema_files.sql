-- ═══════════════════════════════════════════════════════════════
-- المرفقات (صور ومستندات) — لجنة متابعة المخالفات، جامعة الطائف
--
-- تُخزَّن الملفات داخل قاعدة البيانات (base64) وتُقرأ/تُكتب فقط عبر دوال
-- آمنة مربوطة بنظام الصلاحيات: الإرفاق يتطلب قدرة submit، والعرض يتطلب view.
-- لا وصول مباشر للملفات (RLS مفعّل بلا policy).
--
-- التشغيل: Supabase → SQL Editor → Run (بعد v2/v3/v4)
-- ملاحظة: مناسب للصور والمستندات المعتادة. للملفات ضخمة الحجم يُفضّل
-- لاحقاً استخدام Supabase Storage عبر Edge Function.
-- ═══════════════════════════════════════════════════════════════

create table if not exists report_files (
  id           bigserial primary key,
  report_id    text,
  file_name    text,
  mime_type    text,
  size_bytes   bigint,
  data_base64  text,
  uploaded_by  text,
  uploaded_at  timestamptz default now()
);
create index if not exists rf_report_idx on report_files(report_id);
alter table report_files enable row level security;

-- إضافة مرفق (قدرة submit) — يتحقّق من وجود البلاغ ويوثّق في التدقيق
create or replace function app_add_file(p_token uuid, p_report_id text, p_file_name text, p_mime text, p_size bigint, p_data text)
returns json language plpgsql security definer as $$
declare m members; r reports;
begin
  select * into m from _member_from_token(p_token);
  if m.id is null or not _can(m.role,'submit') then return json_build_object('ok', false, 'error', 'unauthorized'); end if;
  select * into r from reports where id = p_report_id;
  if r.id is null then return json_build_object('ok', false, 'error', 'not_found'); end if;
  insert into report_files(report_id, file_name, mime_type, size_bytes, data_base64, uploaded_by)
    values (p_report_id, p_file_name, p_mime, p_size, p_data, m.display_name);
  perform _audit2(m.display_name, m.username, m.role, 'update', p_report_id, r.student_name,
    'إرفاق ملف: ' || coalesce(p_file_name,''), null, null);
  return json_build_object('ok', true);
end; $$;

-- قائمة المرفقات (بيانات وصفية فقط — بلا محتوى) — قدرة view
create or replace function app_list_files(p_token uuid, p_report_id text)
returns table(id bigint, file_name text, mime_type text, size_bytes bigint, uploaded_by text, uploaded_at timestamptz)
language plpgsql security definer as $$
declare m members;
begin
  select * into m from _member_from_token(p_token);
  if m.id is null or not _can(m.role,'view') then return; end if;
  return query select f.id, f.file_name, f.mime_type, f.size_bytes, f.uploaded_by, f.uploaded_at
    from report_files f where f.report_id = p_report_id order by f.uploaded_at;
end; $$;

-- جلب محتوى ملف واحد (base64) — قدرة view
create or replace function app_get_file(p_token uuid, p_id bigint)
returns json language plpgsql security definer as $$
declare m members; f report_files;
begin
  select * into m from _member_from_token(p_token);
  if m.id is null or not _can(m.role,'view') then return json_build_object('ok', false, 'error', 'unauthorized'); end if;
  select * into f from report_files where id = p_id;
  if f.id is null then return json_build_object('ok', false, 'error', 'not_found'); end if;
  return json_build_object('ok', true, 'file_name', f.file_name, 'mime_type', f.mime_type, 'data', f.data_base64);
end; $$;

grant execute on function app_add_file(uuid,text,text,text,bigint,text) to anon;
grant execute on function app_list_files(uuid,text)                    to anon;
grant execute on function app_get_file(uuid,bigint)                    to anon;

-- تم ✓
