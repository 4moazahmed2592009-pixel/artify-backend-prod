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

// 1. حماية CORS
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

// متغيرات البيئة الأساسية - بدون أي قيمة احتياطية خطيرة
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const JWT_SECRET = process.env.JWT_SECRET;
const MONGODB_URI = process.env.MONGODB_URI;
const WHOP_WEBHOOK_SECRET = process.env.WHOP_WEBHOOK_SECRET;

// تأمين: إيقاف السيرفر لو أي متغير أساسي غير موجود
const REQUIRED = { GOOGLE_CLIENT_ID, JWT_SECRET, MONGODB_URI, WHOP_WEBHOOK_SECRET };
const missing = Object.entries(REQUIRED).filter(([, v]) => !v).map(([k]) => k);
if (missing.length) {
  console.error(`FATAL ERROR: Missing required environment variables: ${missing.join(', ')}`);
  process.exit(1);
}

const googleClient = new OAuth2Client(GOOGLE_CLIENT_ID);
const isProd = process.env.NODE_ENV === 'production';

// اسم كوبون المكافأة المجانية (أول 15 مستخدم) - داخلي بالكامل، لا يُرسل أو يُعرض للعميل أبداً
const EARLY_BIRD_CODE = 'EARLY_BIRD_INTERNAL';
const EARLY_BIRD_MAX_SEATS = 15;
const EARLY_BIRD_DURATION_DAYS = 30;

// تحسين الاتصال بقاعدة البيانات لبيئة Serverless
let dbClient = null;
async function getDb() {
  if (!dbClient) {
    dbClient = new MongoClient(MONGODB_URI);
    await dbClient.connect();
  }
  return dbClient.db('artify');
}

// ==========================================
// Middleware مصادقة موحّد يُعاد استخدامه في كل مسار محمي
// ==========================================
function requireAuth(req, res, next) {
  try {
    const token = req.cookies.token;
    if (!token) return res.status(401).json({ error: 'Authentication required' });
    const decoded = jwt.verify(token, JWT_SECRET);
    req.userEmail = decoded.email.toLowerCase();
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid session' });
  }
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
      secure: isProd,
      sameSite: isProd ? 'none' : 'lax',
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
app.get('/api/me', requireAuth, async (req, res) => {
  try {
    const db = await getDb();
    const user = await db.collection('users').findOne({ email: req.userEmail });

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
    res.status(500).json({ error: 'Failed to fetch session' });
  }
});

// ==========================================
// التحقق من توقيع Whop (Standard Webhooks spec)
// التوقيع = base64(HMAC-SHA256("{webhook-id}.{webhook-timestamp}.{raw-body}", secret))
// الهيدر: webhook-signature: v1,<signature> (قد يحتوي أكثر من توقيع مفصولة بمسافة عند دوران المفتاح)
// السرّ بصيغة ws_... يُشتق منه المفتاح الخام بفك base64 للجزء الذي بعد البادئة
// ==========================================
function verifyWhopSignature(req) {
  const webhookId = req.headers['webhook-id'];
  const webhookTimestamp = req.headers['webhook-timestamp'];
  const signatureHeader = req.headers['webhook-signature'];

  if (!webhookId || !webhookTimestamp || !signatureHeader) {
    return { valid: false, reason: 'Missing signature headers' };
  }

  // رفض أي طلب عمره أكثر من 5 دقائق لمنع إعادة إرسال الطلبات القديمة (replay attacks)
  const tsSeconds = parseInt(webhookTimestamp, 10);
  const nowSeconds = Math.floor(Date.now() / 1000);
  if (!tsSeconds || Math.abs(nowSeconds - tsSeconds) > 5 * 60) {
    return { valid: false, reason: 'Timestamp out of tolerance' };
  }

  const secretBytes = WHOP_WEBHOOK_SECRET.startsWith('ws_')
    ? Buffer.from(WHOP_WEBHOOK_SECRET.slice(3), 'base64')
    : Buffer.from(WHOP_WEBHOOK_SECRET, 'base64');

  const rawBody = req.rawBody ? req.rawBody.toString('utf8') : JSON.stringify(req.body);
  const signedContent = `${webhookId}.${webhookTimestamp}.${rawBody}`;
  const expectedSignature = crypto.createHmac('sha256', secretBytes).update(signedContent).digest('base64');

  // الهيدر قد يحتوي أكثر من توقيع مفصولة بمسافة: "v1,sigA v1,sigB"
  const candidates = signatureHeader.split(' ').map(part => part.split(',')[1]).filter(Boolean);

  const isValid = candidates.some(sig => {
    try {
      return crypto.timingSafeEqual(Buffer.from(sig, 'base64'), Buffer.from(expectedSignature, 'base64'));
    } catch {
      return false;
    }
  });

  return { valid: isValid, reason: isValid ? null : 'Signature mismatch' };
}

// ==========================================
// Webhook الدفع المؤمن
// ==========================================
app.post('/api/whop-webhook', async (req, res) => {
  try {
    // لا يوجد أي تخطي: WHOP_WEBHOOK_SECRET مضمون وجوده بفضل الفحص عند إقلاع السيرفر
    const verification = verifyWhopSignature(req);
    if (!verification.valid) {
      console.warn('Webhook rejected:', verification.reason);
      return res.status(401).json({ error: 'Invalid signature' });
    }

    const event = req.body;
    const action = event.action || event.type;
    const data = event.data || event;

    if (!data) return res.status(200).json({ received: true });

    const email = (data.user?.email || data.member?.email || data.email || '').toLowerCase();
    const planId = data.plan_id || (data.plan && data.plan.id) || (data.line_items && data.line_items[0]?.plan_id) || '';

    if (!email) return res.status(200).json({ received: true, note: 'No email found' });

    const db = await getDb();
    const users = db.collection('users');
    const now = Date.now();

    // ربط الـ Plan ID بمدته الفعلية
    let durationDays = 30; // افتراضي شهر لو لم يُعرف الـ Plan ID (يُسجَّل تحذير أدناه)
    if (planId === 'plan_hhPYAFHhQnZ2p') durationDays = 90;
    else if (planId === 'plan_SFcazKZDf63GC') durationDays = 180;
    else if (planId === 'plan_PJeLIwlopBsLV') durationDays = 365;
    else if (planId === 'plan_1AFMWzPSMlWF7') durationDays = 30;
    else if (planId) console.warn(`Unknown Whop plan_id: ${planId}, defaulting to 30 days`);

    const durationMs = durationDays * 24 * 60 * 60 * 1000;

    if (action === 'membership.activated' || action === 'payment.succeeded') {
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
        { $set: { subscription_active: false, plan: 'free', updated_at: now } }
      );
      console.log(`Subscription deactivated for ${email}`);
    }

    res.status(200).json({ success: true });
  } catch (err) {
    console.error('Webhook processing error:', err);
    // نرد 200 بعد التحقق الناجح من التوقيع حتى لا يعيد Whop إرسال نفس الحدث لأسباب داخلية لدينا
    res.status(200).json({ error: 'Webhook error handled' });
  }
});

// ==========================================
// تطبيق كود تفعيل يدوي (يبقى متاحاً كما كان لأكواد الشركاء/الحملات الأخرى)
// ==========================================
app.post('/api/apply-coupon', requireAuth, async (req, res) => {
  try {
    const email = req.userEmail;
    const { couponCode } = req.body;

    if (!couponCode) return res.status(400).json({ error: 'يرجى إدخال الكود' });

    const cleanCode = couponCode.trim().toUpperCase();

    // منع استخدام كود المكافأة الداخلي (أول 15 مستخدم) عبر هذا المسار العام
    // - يجب أن يمر فقط عبر /api/claim-early-bird الذي لا يحتاج العميل لمعرفة اسم الكود
    if (cleanCode === EARLY_BIRD_CODE) {
      return res.status(400).json({ error: 'كود التفعيل غير صحيح' });
    }

    const db = await getDb();
    const coupons = db.collection('coupons');
    const users = db.collection('users');

    const coupon = await coupons.findOne({ code: cleanCode });
    if (!coupon) return res.status(404).json({ error: 'كود التفعيل غير صحيح' });

    if (coupon.used_count >= coupon.max_uses) {
      return res.status(400).json({ error: 'عذراً، نفدت المقاعد المجانية المتاحة لهذا الكود' });
    }

    const updateResult = await coupons.updateOne(
      { code: cleanCode, used_count: { $lt: coupon.max_uses } },
      { $inc: { used_count: 1 } }
    );

    if (updateResult.modifiedCount === 0) {
      return res.status(400).json({ error: 'عذراً، نفدت المقاعد المجانية المتاحة لهذا الكود' });
    }

    const now = Date.now();
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

    res.json({ success: true, type: 'free', message: 'تم تفعيل حساب PRO بنجاح!' });
  } catch (err) {
    res.status(500).json({ error: 'فشل تطبيق الكود' });
  }
});

// ==========================================
// مطالبة "أول 15 مستخدم" - بدون أي كود يُرسل من العميل إطلاقاً
// السيرفر هو المصدر الوحيد للحقيقة: يتحقق داخلياً من عدد المقاعد المتبقية
// ==========================================
app.post('/api/claim-early-bird', requireAuth, async (req, res) => {
  try {
    const email = req.userEmail;
    const db = await getDb();
    const coupons = db.collection('coupons');
    const users = db.collection('users');

    // إنشاء الكوبون الداخلي تلقائياً أول مرة لو لم يكن موجوداً
    let coupon = await coupons.findOne({ code: EARLY_BIRD_CODE });
    if (!coupon) {
      await coupons.insertOne({
        code: EARLY_BIRD_CODE,
        max_uses: EARLY_BIRD_MAX_SEATS,
        used_count: 0,
        duration_days: EARLY_BIRD_DURATION_DAYS,
        type: 'free',
        created_at: Date.now()
      });
      coupon = await coupons.findOne({ code: EARLY_BIRD_CODE });
    }

    // منع نفس المستخدم من المطالبة أكثر من مرة
    const existingUser = await users.findOne({ email });
    if (existingUser?.early_bird_claimed) {
      return res.status(400).json({ error: 'لقد استخدمت مكافأة أول 15 مستخدم من قبل' });
    }

    if (coupon.used_count >= coupon.max_uses) {
      return res.status(400).json({ error: 'عذراً، نفدت المقاعد المجانية المتاحة' });
    }

    // تحديث ذرّي (Atomic) لمنع Race Condition عند التزاحم على آخر مقعد
    const updateResult = await coupons.updateOne(
      { code: EARLY_BIRD_CODE, used_count: { $lt: EARLY_BIRD_MAX_SEATS } },
      { $inc: { used_count: 1 } }
    );

    if (updateResult.modifiedCount === 0) {
      return res.status(400).json({ error: 'عذراً، نفدت المقاعد المجانية المتاحة' });
    }

    const now = Date.now();
    const durationMs = EARLY_BIRD_DURATION_DAYS * 24 * 60 * 60 * 1000;
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
          early_bird_claimed: true,
          updated_at: now
        }
      },
      { upsert: true }
    );

    res.json({ success: true, message: 'تم تفعيل حساب PRO بنجاح!' });
  } catch (err) {
    console.error('Claim early bird error:', err);
    res.status(500).json({ error: 'حدث خطأ أثناء التفعيل' });
  }
});

// ==========================================
// إحصائيات المقاعد المجانية (اسم الكود لا يُعرض هنا أبداً)
// ==========================================
app.get('/api/promo-stats', async (req, res) => {
  try {
    const db = await getDb();
    const coupon = await db.collection('coupons').findOne({ code: EARLY_BIRD_CODE });
    if (!coupon) return res.json({ active: true, remaining: EARLY_BIRD_MAX_SEATS, currentRank: 1 });

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
// تشغيل الأداة
// ==========================================
app.get('/api/launch-app', async (req, res) => {
  try {
    const token = req.cookies.token;
    if (!token) return res.redirect('/?error=unauthorized');

    const decoded = jwt.verify(token, JWT_SECRET);
    const db = await getDb();
    const user = await db.collection('users').findOne({ email: decoded.email.toLowerCase() });

    if (!user || !user.subscription_active || user.expires_at <= Date.now()) {
      return res.redirect('/?error=subscription_required');
    }

    res.redirect(process.env.TOOL_URL || 'https://script.google.com/macros/s/AKfycby9D8zK3a2uM_4oJ_f1W6oH7L-U4VqL-9nE-demo/exec');
  } catch (err) {
    console.error('Launch error:', err);
    res.redirect('/?error=access_denied');
  }
});

// ==========================================
// تسجيل الخروج وحذف الحساب
// ==========================================
app.post('/api/logout', (req, res) => {
  res.clearCookie('token', { sameSite: isProd ? 'none' : 'lax', secure: isProd });
  res.json({ success: true });
});

app.post('/api/delete-account', requireAuth, async (req, res) => {
  try {
    const db = await getDb();
    await db.collection('users').deleteOne({ email: req.userEmail });

    res.clearCookie('token', { sameSite: isProd ? 'none' : 'lax', secure: isProd });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Delete failed' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running securely on port ${PORT} (Prod Mode: ${isProd})`);
});

export default app;
