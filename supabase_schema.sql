-- ============================================================
--  🗄️ PDF Verifier - Supabase Table Setup
--  Run this SQL in: Supabase → SQL Editor → New Query
-- ============================================================

-- جدول تسجيل الإيصالات الإيداع المتحقق منها
-- يمنع إعادة استخدام نفس الإيصال مرتين

CREATE TABLE IF NOT EXISTS verified_receipts (
    id              BIGSERIAL PRIMARY KEY,
    receipt_number  TEXT NOT NULL UNIQUE,   -- رقم الإشعار (مثال: 8-168661341)
    dest_account    TEXT,                   -- رقم حساب المستلم
    amount          TEXT,                   -- المبلغ المودع
    receipt_date    TEXT,                   -- تاريخ الإيصال (YYYY/MM/DD)
    file_size_kb    NUMERIC(10,2),          -- حجم الملف (للمرجع)
    verified_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()  -- وقت التحقق
);

-- فهرس سريع على رقم الإشعار (هو الأكثر استخداماً في البحث)
CREATE INDEX IF NOT EXISTS idx_verified_receipts_receipt_number
    ON verified_receipts (receipt_number);

-- فهرس على رقم حساب المستلم (للبحث والتقارير)
CREATE INDEX IF NOT EXISTS idx_verified_receipts_dest_account
    ON verified_receipts (dest_account);

-- فهرس على وقت التحقق (للتقارير الزمنية)
CREATE INDEX IF NOT EXISTS idx_verified_receipts_verified_at
    ON verified_receipts (verified_at DESC);

-- ============================================================
--  🔒 Row Level Security (RLS)
--  الخدمة تستخدم service_role key فقط → تجاوز RLS تلقائياً
--  لكن نُفعّل RLS ونمنع الوصول العام لأمان إضافي
-- ============================================================

ALTER TABLE verified_receipts ENABLE ROW LEVEL SECURITY;

-- لا يُسمح بأي عملية قراءة/كتابة عبر anon key
-- (الوصول يتم فقط عبر service_role key من الخادم)
CREATE POLICY "deny_public_access" ON verified_receipts
    FOR ALL
    TO anon
    USING (false);
