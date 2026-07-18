# طبقة الخادم الآمنة (Supabase Edge Functions)

هذه دوال حافة جاهزة للنشر على حساب Supabase الخاص بالجامعة، لتفعيل ما لا يمكن
تنفيذه من «صفحة ثابتة + مفتاح عام»: **التقاط عنوان IP**، **حدّ المحاولات على
البوابة**، و**التحقق الثنائي OTP** (سكافولد).

كل شيء داخل هذا المجلّد اختياري — المنصة تعمل بدونه، وتفعيله لا يكسر أي ميزة.

---

## ١) الدخول الآمن + التقاط IP  (`login-secure`) — جاهز للإنتاج

يلتقط IP والجهاز/المتصفح، ويطبّق حدّ ٢٠ محاولة/١٠ دقائق لكل IP، ويسجّل IP في
سجل التدقيق.

**الخطوات:**
1. في SQL Editor: شغّلي `schema_edge.sql`.
2. ثبّتي Supabase CLI ثم:
   ```bash
   supabase login
   supabase link --project-ref bplxjiiauxeviqrvkygh
   supabase functions deploy login-secure --no-verify-jwt
   ```
3. انسخي رابط الدالة (يظهر بعد النشر، بالشكل):
   `https://bplxjiiauxeviqrvkygh.functions.supabase.co/login-secure`
4. في `index.html` (أو `violations-committee.html`) اضبطي الثابت:
   ```js
   const EDGE_LOGIN_URL = 'https://bplxjiiauxeviqrvkygh.functions.supabase.co/login-secure';
   ```
   عندها ينتقل الدخول عبر البوابة، ويظهر عمود IP في «سجل التدقيق» تلقائياً.

> ملاحظة أمان: `app_login_ip` مسحوبة من `anon` عمداً — تُستدعى فقط من الدالة
> بمفتاح الخدمة، فلا يستطيع العميل تزوير الـ IP.

---

## ٢) التحقق الثنائي OTP بالبريد  (`otp`) — سكافولد

يتطلّب مزوّد بريد (المثال يستخدم Resend) وحقل بريد لكل عضو، وربط تدفّق دخول من
مرحلتين في الواجهة (طلب رمز ← إدخال الرمز). سُلّم كـ«هيكل جاهز للربط» لأن الـ OTP
الحقيقي لا يكتمل دون مزوّد رسائل/بريد.

**الخطوات:**
1. شغّلي `otp/schema_otp.sql` وأضيفي بريد كل عضو في عمود `members.email`.
2. أنشئي حساب Resend ووثّقي نطاق الإرسال، ثم:
   ```bash
   supabase secrets set RESEND_API_KEY=xxxxxxxx
   supabase functions deploy mfa --no-verify-jwt
   ```
3. عدّلي `SENDER` في `otp/index.ts` إلى نطاقك الموثّق.
4. اربطي الواجهة: بعد التحقق من كلمة السر، استدعي `mfa?action=request` ثم اطلبي
   الرمز من المستخدم وتحقّقي عبر `mfa?action=verify` قبل إنشاء الجلسة.

---

## ٣) الامتثال ECC

الضوابط التقنية (تحكّم وصول، تدقيق لا يُعدّل، قفل حساب، تشفير، حدّ محاولات،
التقاط IP، CSP) مُطبّقة. أما «الامتثال» فهو اعتماد تنظيمي لجهة عبر مراجعة وتوثيق
واختبار اختراق — خطوة إجرائية وليست كوداً.
