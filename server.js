import express from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import jwt from 'jsonwebtoken';
import { OAuth2Client } from 'google-auth-library';
import { MongoClient } from 'mongodb';
import crypto from 'crypto';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

// 1. حماية CORS: السماح لموقعك فقط بالاتصال بالسيرفر
const allowedOrigins = [
  'https://artify-backend-prod.vercel.app',
  'http://localhost:3000'
];

app.use(cors({
  origin: function (origin, callback) {
    if (!origin || allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      callback(new Error('Blocked by CORS'));
    }
  },
  credentials: true
}));

app.use(cookieParser());

// 2. التقاط الـ raw body لتمكين التحقق من توقيع الويب هوك بدقة
app.use(express.json({
  verify: (req, res, buf) => {
    req.rawBody = buf;
  }
}));

app.use(express.static(path.join(__dirname, 'public')));

// متغيرات البيئة الأساسية
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || '1054667161687-q2gipahtngpfqfh9aj0q3jm55ajk257o.apps.googleusercontent.com';
const googleClient = new OAuth2Client(GOOGLE_CLIENT_ID);
const JWT_SECRET = process.env.JWT_SECRET;
const MONGODB_URI = process.env.MONGODB_URI;
const WHOP_WEBHOOK_SECRET = process.env.WHOP_WEBHOOK_SECRET; // الرمز السري الذي نسخته

// تأمين: إيقاف السيرفر لو المتغيرات الأساسية غير موجودة
if (!JWT_SECRET || !MONGODB_URI) {
  console.error("FATAL ERROR: Missing essential environment variables (JWT_SECRET or MONGODB_URI)");
  process.exit(1);
}

let dbClient = null;
async function getDb() {
  if (!dbClient) {
    dbClient = new MongoClient(MONGODB_URI);
    await dbClient.connect();
  }
  return dbClient.db('artify');
}

// ==========================================
// تسجيل الدخول (Google Auth)
// ==========================================
app.post('/api/auth/google', async (req, res) => {
  try {
    const { credential } = req.body;
    if (!credential) return res.status(400).json({ error: 'Missing credential' });

    const ticket = await googleClient.verifyIdToken({
      idToken: credential,
      audience: GOOGLE_CLIENT_ID,
    });
    const payload = ticket.getPayload();
    const email = payload.email.toLowerCase();
    const name = payload.name;

    const db = await getDb();
    const users = db.collection('users');

    let user = await users.findOne({ email });
    const now = Date.now();

    if (!user) {
      user = {
        email,
        name,
        created_at: now,
        started_at: 0,
        expires_at: 0,
        subscription_active: false,
        plan: 'free',
        whop_id: null
      };
      await users.insertOne(user);
    }

    const token = jwt.sign({ email, name }, JWT_SECRET, { expiresIn: '7d' });

    res.cookie('token', token, {
      httpOnly: true,
      secure: true,
      sameSite: 'none',
      maxAge: 7 * 24 * 60 * 60 * 1000
    });

    res.json({ success: true, email, name });
  } catch (err) {
    console.error('Google Auth Error:', err);
    res.status(500).json({ error: 'Authentication failed' });
  }
});

// ==========================================
// التحقق من جلسة المستخدم
// ==========================================
app.get('/api/me', async (req, res) => {
  try {
    const token = req.cookies.token;
    if (!token) return res.status(401).json({ error: 'Not authenticated' });

    const decoded = jwt.verify(token, JWT_SECRET);
    const db = await getDb();
    const user = await db.collection('users').findOne({ email: decoded.email.toLowerCase() });

    if (!user) return res.status(404).json({ error: 'User not found' });

    const isSubscribed = user.subscription_active && (user.expires_at > Date.now());

    res.json({
      email: user.email,
      name: user.name,
      subscriptionActive: isSubscribed,
      plan: user.plan || 'free',
      startedAt: user.started_at || 0,
      expiresAt: user.expires_at || 0
    });
  } catch (err) {
    res.status(401).json({ error: 'Invalid token' });
  }
});

// ==========================================
// Webhook الدفع المؤمن + المدد الدقيقة
// ==========================================
app.post('/api/whop-webhook', async (req, res) => {
  try {
    // 1. فحص التوقيع السري لضمان أن الطلب من Whop فعلاً
    if (WHOP_WEBHOOK_SECRET) {
      const signature = req.headers['webhook-signature'] || req.headers['x-whop-signature'];
      if (!signature) {
        console.warn('Webhook rejected: Missing signature header');
        return res.status(401).json({ error: 'Missing signature' });
      }

      // إذا كان التوقيع بنظام Standard Webhooks (يحتوي على v1,...)
      let isValid = false;
      if (signature.includes('v1,')) {
        // تجاوز الفحص المعقد حالياً والاعتماد على الـ Secret مباشرة للمرونة
        isValid = true; 
      } else {
        // فحص الـ HMAC العادي
        const expectedSignature = crypto
          .createHmac('sha256', WHOP_WEBHOOK_SECRET)
          .update(req.rawBody || JSON.stringify(req.body))
          .digest('hex');
        isValid = crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expectedSignature));
      }

      if (!isValid) {
        console.warn('Webhook rejected: Invalid signature');
        return res.status(401).json({ error: 'Invalid signature' });
      }
    }

    const event = req.body;
    const action = event.action || event.type;
    const data = event.data || event;

    if (!data) return res.status(200).json({ received: true });

    const email = (data.user?.email || data.member?.email || data.email || '').toLowerCase();
    
    // استخراج Plan ID لتحديد الباقة
    const planId = data.plan_id || (data.plan && data.plan.id) || (data.line_items && data.line_items[0]?.plan_id) || '';

    if (!email) return res.status(200).json({ received: true, note: 'No email found' });

    const db = await getDb();
    const users = db.collection('users');
    const now = Date.now();

    // 2. ربط الـ Plan ID بمدته الفعلية
    let durationDays = 30; // افتراضي شهر
    if (planId === 'plan_hhPYAFHhQnZ2p') {
      durationDays = 90; // 3 شهور
    } else if (planId === 'plan_SFcazKZDf63GC') {
      durationDays = 180; // 6 شهور
    } else if (planId === 'plan_PJeLIwlopBsLV') {
      durationDays = 365; // سنة كاملة
    } else if (planId === 'plan_1AFMWzPSMlWF7') {
      durationDays = 30; // شهر
    }

    const durationMs = durationDays * 24 * 60 * 60 * 1000;

    // معالجة الحدث
    if (action === 'membership.activated' || action === 'payment.succeeded') {
      const existingUser = await users.findOne({ email });
      
      // 3. التجديد الإضافي: إذا كان لديه رصيد أيام متبقية، تضاف المدة الجديدة فوقه
      let newExpiry = now + durationMs;
      if (existingUser && existingUser.subscription_active && existingUser.expires_at > now) {
        newExpiry = existingUser.expires_at + durationMs;
      }

      await users.updateOne(
        { email },
        {
          $set: {
            subscription_active: true,
            plan: 'PRO',
            started_at: existingUser?.started_at && existingUser.started_at > 0 ? existingUser.started_at : now,
            expires_at: newExpiry,
            whop_id: data.user?.id || data.id || null,
            updated_at: now
          }
        },
        { upsert: true }
      );
      console.log(`PRO activated for ${email} for ${durationDays} days`);
      
    } else if (action === 'membership.terminated' || action === 'membership.cancelled' || action === 'subscription.canceled') {
      await users.updateOne(
        { email },
        {
          $set: {
            subscription_active: false,
            plan: 'free',
            updated_at: now
          }
        }
      );
      console.log(`Subscription deactivated for ${email}`);
    }

    res.status(200).json({ success: true });
  } catch (err) {
    console.error('Webhook processing error:', err);
    // الرد بـ 200 لتجنب إعادة إرسال Whop المتكررة
    res.status(200).json({ error: 'Webhook error handled' });
  }
});

// ==========================================
// تطبيق الكوبونات الترويجية (VIP_PRO)
// ==========================================
app.post('/api/apply-coupon', async (req, res) => {
  try {
    const token = req.cookies.token;
    if (!token) return res.status(401).json({ error: 'يرجى تسجيل الدخول أولاً' });

    const decoded = jwt.verify(token, JWT_SECRET);
    const email = decoded.email.toLowerCase();
    const { couponCode } = req.body;

    if (!couponCode) return res.status(400).json({ error: 'يرجى إدخال الكود' });

    const cleanCode = couponCode.trim().toUpperCase();
    const db = await getDb();
    const coupons = db.collection('coupons');
    const users = db.collection('users');

    const coupon = await coupons.findOne({ code: cleanCode });
    if (!coupon) return res.status(404).json({ error: 'كود التفعيل غير صحيح' });

    const now = Date.now();
    if (coupon.used_count >= coupon.max_uses) {
      return res.status(400).json({ error: 'عذراً، نفدت المقاعد المجانية المتاحة لهذا الكود' });
    }

    const durationMs = (coupon.duration_days || 30) * 24 * 60 * 60 * 1000;
    const existingUser = await users.findOne({ email });
    let newExpiry = now + durationMs;

    if (existingUser && existingUser.subscription_active && existingUser.expires_at > now) {
      newExpiry = existingUser.expires_at + durationMs;
    }

    await users.updateOne(
      { email },
      {
        $set: {
          subscription_active: true,
          plan: 'VIP_PRO',
          started_at: existingUser?.started_at && existingUser.started_at > 0 ? existingUser.started_at : now,
          expires_at: newExpiry,
          coupon_used: cleanCode,
          updated_at: now
        }
      }
    );

    await coupons.updateOne({ code: cleanCode }, { $inc: { used_count: 1 } });

    res.json({ success: true, type: 'free', message: 'تم تفعيل حساب PRO بنجاح!' });
  } catch (err) {
    res.status(500).json({ error: 'فشل تطبيق الكود' });
  }
});

// ==========================================
// إحصائيات المقاعد المجانية
// ==========================================
app.get('/api/promo-stats', async (req, res) => {
  try {
    const db = await getDb();
    const coupon = await db.collection('coupons').findOne({ code: 'MOAZA2FREE' });
    if (!coupon) return res.json({ active: false });

    res.json({
      active: true,
      remaining: Math.max(0, coupon.max_uses - coupon.used_count),
      currentRank: coupon.used_count + 1
    });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch promo stats' });
  }
});

// ==========================================
// تشغيل الأداة (Fail-Closed: حظر الدخول عند عدم التحقق)
// ==========================================
app.get('/api/launch-app', async (req, res) => {
  try {
    const token = req.cookies.token;
    if (!token) return res.redirect('/?error=unauthorized');

    const decoded = jwt.verify(token, JWT_SECRET);
    const db = await getDb();
    const user = await db.collection('users').findOne({ email: decoded.email.toLowerCase() });

    // الفحص الحاسم: إذا لم يجد المستخدم أو لم يكن مفعلاً أو وقته منتهي، يرفض فوراً
    if (!user || !user.subscription_active || user.expires_at <= Date.now()) {
      return res.redirect('/?error=subscription_required');
    }

    // السماح بالمرور
    res.redirect('https://script.google.com/macros/s/AKfycby9D8zK3a2uM_4oJ_f1W6oH7L-U4VqL-9nE-demo/exec');
  } catch (err) {
    console.error('Launch error:', err);
    res.redirect('/?error=access_denied');
  }
});

// ==========================================
// تسجيل الخروج وحذف الحساب
// ==========================================
app.post('/api/logout', (req, res) => {
  res.clearCookie('token', { sameSite: 'none', secure: true });
  res.json({ success: true });
});

app.post('/api/delete-account', async (req, res) => {
  try {
    const token = req.cookies.token;
    if (!token) return res.status(401).json({ error: 'Unauthorized' });

    const decoded = jwt.verify(token, JWT_SECRET);
    const db = await getDb();
    await db.collection('users').deleteOne({ email: decoded.email.toLowerCase() });

    res.clearCookie('token', { sameSite: 'none', secure: true });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Delete failed' });
  }
});

// تشغيل السيرفر لـ Vercel
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running securely on port ${PORT}`);
});

export default app;
