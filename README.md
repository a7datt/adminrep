# مشروع الآدمن (Admin App)

لوحة تحكم المسؤول — منفصلة تماماً عن مشروع العملاء.

## الملفات المهمة

| الملف | الوصف |
|-------|-------|
| `server.ts` | السيرفر — يشمل route واحد فقط: `/api/admin` |
| `src/App.tsx` | الراوتر الأمامي — صفحة `/admin` فقط |
| `.env.example` | نسخه إلى `.env` وأضف قيمك |

## إعداد المشروع

### 1. تثبيت الحزم
```bash
npm install
```

### 2. إعداد متغيرات البيئة
```bash
cp .env.example .env
# عدّل .env وأضف قيمك الحقيقية
```

### المتغيرات المطلوبة
| المتغير | الوصف |
|---------|-------|
| `VITE_SUPABASE_URL` | نفس رابط Supabase المستخدم في مشروع العملاء |
| `SUPABASE_SERVICE_ROLE_KEY` | نفس مفتاح Supabase Service Role |
| `ADMIN_JWT_SECRET` | سر JWT للآدمن — **يجب أن يختلف** عن JWT_SECRET في مشروع العملاء |
| `ALLOWED_ORIGINS` | نطاق لوحة الآدمن فقط (مثل: https://admin.yourdomain.com) |

> ⚠️ **تنبيه أمان**: `ADMIN_JWT_SECRET` يجب أن يكون مختلفاً تماماً عن `JWT_SECRET` و `JWT_REFRESH_SECRET` في مشروع العملاء.

### 3. تطوير محلي
```bash
npm run dev
# يعمل على http://localhost:4000  (بورت مختلف عن العملاء)
```

### 4. بناء للإنتاج
```bash
npm run build
npm start
```

## هيكل المشروع

```
admin-project/
├── server.ts              # السيرفر (Express) — /api/admin فقط
├── src/
│   ├── App.tsx            # الراوتر → /admin
│   ├── main.tsx
│   ├── pages/
│   │   └── Admin.tsx      # لوحة الإدارة الكاملة
│   └── server/
│       ├── routes/
│       │   └── admin.ts   # جميع routes الآدمن
│       ├── middleware.ts
│       ├── cron.ts
│       └── db.ts
```

## الرابط

بعد الرفع، لوحة الآدمن ستكون على: `https://admin.yourdomain.com/admin`
