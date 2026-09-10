const express = require('express');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { OAuth2Client } = require('google-auth-library');
const mongoose = require('mongoose');
const path = require('path');

const app = express();

// ==========================================
// 0. متغيرات البيئة الإلزامية (السيرفر يرفض يشتغل لو ناقصة بدل ما يستخدم قيم افتراضية خطيرة)
// ==========================================
const REQUIRED_ENV = ['JWT_SECRET', 'GOOGLE_CLIENT_ID', 'MONGODB_URI', 'WHOP_WEBHOOK_SECRET', 'ALLOWED_ORIGIN'];
const missingEnv = REQUIRED_ENV.filter((key) => !process.env[key]);
if (missingEnv.length) {
  console.error(`❌ متغيرات بيئة ناقصة، السيرفر لن يبدأ: ${missingEnv.join(', ')}`);
  process.exit(1);
}

const JWT_SECRET = process.env.JWT_SECRET;
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const WHOP_WEBHOOK_SECRET = process.env.WHOP_WEBHOOK_SECRET; // القيمة تبدأ بـ ws_... لا تُعدّل أو تُشفّر يدوياً
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN; // مثال: https://artify-backend-prod.vercel.app
const googleClient = new OAuth2Client(GOOGLE_CLIENT_ID);

// ==========================================
// 1. CORS مقيّد على دومين الواجهة فقط (بدل origin: true المفتوح للجميع)
// ==========================================
app.use(cors({
  origin: ALLOWED_ORIGIN,
  credentials: true,
}));

// ==========================================
// 2. مسار الـ Webhook: لازم يُسجَّل قبل express.json() العام
// لأن التحقق من التوقيع يحتاج الـ body الخام (raw) بالظبط زي ما وصل،
// وأي parsing مسبق للـ JSON بيغيّر البايتات ويكسر التحقق.
// ==========================================
app.post('/api/whop-webhook', express.raw({ type: 'application/json' }), (req, res) => {
  handleWhopWebhook(req, res).catch((err) => {
    console.error('❌ Whop Webhook Error:', err);
    // لو حصل خطأ غير متوقع بعد التحقق، لسه المفروض نرد 200 عشان Whop ميعيدش المحاولة بلا داعي
    // لكن لو التحقق نفسه فشل بنرجع خطأ من جوه handleWhopWebhook قبل ما نوصل هنا
    if (!res.headersSent) res.status(500).send('Webhook Processing Error');
  });
});

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// ==========================================
// 3. الجداول (Models)
// ==========================================
const userSchema = new mongoose.Schema({
  email: { type: String, unique: true, required: true },
  name: { type: String, default: '' },
  subscription_active: { type: Boolean, default: false },
  plan: { type: String, default: 'free' },
  started_at: { type: Number, default: 0 },
  expires_at: { type: Number, default: 0 },
  auto_renew: { type: Boolean, default: true },
  couponUsed: { type: String, default: '' },
  processed_webhook_ids: [String]
}, { timestamps: true });
const User = mongoose.models.User || mongoose.model('User', userSchema);

const couponSchema = new mongoose.Schema({
  code: { type: String, unique: true, required: true },
  type: { type: String, enum: ['free', 'percent'], required: true },
  discount: { type: Number, default: 0 },
  maxUses: { type: Number, default: 15 },
  usedCount: { type: Number, default: 0 },
  active: { type: Boolean, default: true }
});
const Coupon = mongoose.models.Coupon || mongoose.model('Coupon', couponSchema);

let isConnected = false;
const connectDB = async () => {
  if (isConnected) return;
  try {
    await mongoose.connect(process.env.MONGODB_URI, { serverSelectionTimeoutMS: 5000 });
    isConnected = true;
    console.log('✅ MongoDB Connected');
  } catch (err) {
    console.error('❌ MongoDB error:', err.message);
    isConnected = false;
  }
};

// ==========================================
// 4. خرائط باقات Whop: كل Plan ID مربوط بمدته الصحيحة بالمللي ثانية
// عدّل هذه القيم فقط لو غيّرت الباقات على Whop
// ==========================================
const DAY_MS = 24 * 60 * 60 * 1000;
const WHOP_PLAN_DURATIONS = {
  'plan_1AFMWzPSMlWF7': { code: 'month1', ms: 30 * DAY_MS },
  'plan_hhPYAFHhQnZ2p': { code: 'month3', ms: 90 * DAY_MS },
  'plan_SFcazKZDf63GC': { code: 'month6', ms: 180 * DAY_MS },
  'plan_PJeLIwlopBsLV': { code: 'year1', ms: 365 * DAY_MS },
};
const DEFAULT_PLAN_MS = 30 * DAY_MS; // احتياطي فقط لو وصل Plan ID غير معروف - يُسجَّل تحذير في اللوج

// ==========================================
// 5. التحقق من توقيع Whop Webhook (Standard Webhooks spec)
// التوقيع = HMAC-SHA256("{webhook-id}.{webhook-timestamp}.{raw-body}", secret) بصيغة base64
// الهيدر بيجي بالشكل: webhook-signature: v1,<signature>
// ==========================================
function verifyWhopSignature(req) {
  const webhookId = req.headers['webhook-id'];
  const webhookTimestamp = req.headers['webhook-timestamp'];
  const webhookSignatureHeader = req.headers['webhook-signature'];

  if (!webhookId || !webhookTimestamp || !webhookSignatureHeader) {
    return { valid: false, reason: 'Missing signature headers' };
  }

  // رفض أي طلب عمره أكتر من 5 دقايق لمنع هجمات إعادة التشغيل (replay attacks)
  const timestampSeconds = parseInt(webhookTimestamp, 10);
  const nowSeconds = Math.floor(Date.now() / 1000);
  if (!timestampSeconds || Math.abs(nowSeconds - timestampSeconds) > 5 * 60) {
    return { valid: false, reason: 'Timestamp out of tolerance' };
  }

  // secret بصيغة ws_... — نشتق منه المفتاح الخام كما توضح مواصفات Standard Webhooks
  const secretBytes = WHOP_WEBHOOK_SECRET.startsWith('ws_')
    ? Buffer.from(WHOP_WEBHOOK_SECRET.slice(3), 'base64')
    : Buffer.from(WHOP_WEBHOOK_SECRET, 'base64');

  const signedContent = `${webhookId}.${webhookTimestamp}.${req.body.toString('utf8')}`;
  const expectedSignature = crypto.createHmac('sha256', secretBytes).update(signedContent).digest('base64');

  // الهيدر ممكن يحتوي أكتر من توقيع مفصولة بمسافة (v1,sig1 v1,sig2) في حالة دوران المفتاح
  const receivedSignatures = webhookSignatureHeader.split(' ').map((part) => part.split(',')[1]).filter(Boolean);

  const isValid = receivedSignatures.some((sig) => {
    try {
      return crypto.timingSafeEqual(Buffer.from(sig, 'base64'), Buffer.from(expectedSignature, 'base64'));
    } catch (e) {
      return false; // أطوال مختلفة = مش متطابقة
    }
  });

  return { valid: isValid, webhookId, reason: isValid ? null : 'Signature mismatch' };
}

async function handleWhopWebhook(req, res) {
  const verification = verifyWhopSignature(req);
  if (!verification.valid) {
    console.warn('⚠️ Whop webhook rejected:', verification.reason);
    return res.status(401).send('Invalid signature');
  }

  const eventData = JSON.parse(req.body.toString('utf8'));
  const webhookId = verification.webhookId;
  console.log('✅ Verified Whop Webhook:', eventData?.type || 'unknown event', webhookId);

  await connectDB();
  if (!isConnected) {
    // لو مش قادرين نوصل لقاعدة البيانات، نرفض بكود يخلي Whop يعيد المحاولة لاحقاً بدل ما نفقد الحدث
    return res.status(503).send('Database unavailable, retry later');
  }

  // معالجة أحداث الدفع الناجح فقط (وسّع القائمة لاحقاً لو احتجت membership.activated مثلاً)
  if (eventData.type !== 'payment.succeeded') {
    return res.status(200).json({ received: true, ignored: eventData.type });
  }

  const paymentData = eventData.data || {};

  let email = paymentData?.member?.email || paymentData?.user?.email || paymentData?.email || '';
  email = (email || '').toLowerCase().trim();
  if (!email) {
    console.warn('⚠️ Whop webhook payment.succeeded بدون إيميل واضح، تم تجاهله.');
    return res.status(200).json({ received: true, skipped: 'no email' });
  }

  // ضمان عدم معالجة نفس الحدث مرتين (Whop بيرسل نفس الحدث أكتر من مرة أحياناً)
  const existingUser = await User.findOne({ email });
  if (existingUser && existingUser.processed_webhook_ids?.includes(webhookId)) {
    return res.status(200).json({ received: true, duplicate: true });
  }

  // استخراج Plan ID من الحمولة (بيختلف مكانه حسب شكل الدفعة، فبنجرب أكتر من مسار محتمل)
  const rawPlanId = paymentData?.plan?.id || paymentData?.plan_id || paymentData?.line_items?.[0]?.plan_id || null;
  const planInfo = rawPlanId && WHOP_PLAN_DURATIONS[rawPlanId] ? WHOP_PLAN_DURATIONS[rawPlanId] : null;

  if (!planInfo) {
    console.warn(`⚠️ Plan ID غير معروف في الـ webhook: ${rawPlanId}. تم استخدام المدة الافتراضية (30 يوم) - راجع خريطة WHOP_PLAN_DURATIONS.`);
  }

  const duration = planInfo ? planInfo.ms : DEFAULT_PLAN_MS;
  const planCode = planInfo ? planInfo.code : 'unknown';
  const now = Date.now();

  const user = existingUser || new User({ email, name: email.split('@')[0] });

  // لو عنده اشتراك شغال بالفعل، المدة الجديدة تُضاف فوق المتبقي بدل ما تلغيه (تجديد مش استبدال)
  const currentExpiry = (user.subscription_active && user.expires_at > now) ? user.expires_at : now;
  user.subscription_active = true;
  user.plan = planCode;
  user.started_at = user.started_at && user.subscription_active ? user.started_at : now;
  user.expires_at = currentExpiry + duration;
  user.processed_webhook_ids = [...(user.processed_webhook_ids || []).slice(-50), webhookId];
  await user.save();

  console.log(`✅ User ${email} activated/renewed via Whop — plan: ${planCode}, expires: ${new Date(user.expires_at).toISOString()}`);
  return res.status(200).json({ received: true });
}

// ==========================================
// 6. تسجيل الدخول (Google Auth)
// ==========================================
app.post('/api/auth/google', async (req, res) => {
  try {
    const { credential } = req.body;
    if (!credential) return res.status(400).json({ error: 'بيانات جوجل مفقودة' });

    const ticket = await googleClient.verifyIdToken({ idToken: credential, audience: GOOGLE_CLIENT_ID });
    const payload = ticket.getPayload();
    const email = payload.email.toLowerCase().trim();
    const name = payload.name || 'User';

    await connectDB();
    if (!isConnected) {
      return res.status(503).json({ error: 'قاعدة البيانات غير متصلة حالياً، حاول مرة أخرى بعد قليل.' });
    }

    let user = await User.findOne({ email });
    if (!user) {
      user = await User.create({ email, name, subscription_active: false, plan: 'free' });
    } else if (name && user.name !== name) {
      user.name = name;
      await user.save();
    }

    const now = Date.now();
    let isSubActive = false;
    let expiresAt = null, startedAt = null, plan = 'free';

    if (user.subscription_active && user.expires_at > now) {
      isSubActive = true;
      expiresAt = user.expires_at;
      startedAt = user.started_at;
      plan = user.plan || 'PRO';
    } else if (user.subscription_active && user.expires_at <= now) {
      user.subscription_active = false;
      user.plan = 'free';
      await user.save();
    }

    const token = jwt.sign({ email, name }, JWT_SECRET, { expiresIn: '30d' });
    res.cookie('session_token', token, { httpOnly: true, secure: true, sameSite: 'none', maxAge: 30 * 24 * 60 * 60 * 1000 });

    return res.json({
      success: true,
      user: { email, name, subscriptionActive: isSubActive, startedAt, expiresAt, plan, autoRenew: user.auto_renew !== false }
    });
  } catch (err) {
    console.error('Auth Error:', err);
    return res.status(500).json({ error: 'حدث خطأ أثناء المصادقة مع جوجل' });
  }
});

const requireAuth = (req, res, next) => {
  const token = req.cookies?.session_token;
  if (!token) return res.status(401).json({ error: 'Authentication required' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.userEmail = decoded.email;
    req.userName = decoded.name;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid session' });
  }
};

app.get('/api/me', async (req, res) => {
  try {
    const token = req.cookies?.session_token;
    if (!token) return res.status(401).json({ error: 'Not authenticated' });

    const decoded = jwt.verify(token, JWT_SECRET);
    await connectDB();
    if (!isConnected) return res.status(503).json({ error: 'Database unavailable' });

    const user = await User.findOne({ email: decoded.email.toLowerCase().trim() });
    if (!user) {
      res.clearCookie('session_token');
      return res.status(401).json({ error: 'User not found' });
    }

    const now = Date.now();
    let isSubActive = false;
    if (user.subscription_active && user.expires_at > now) {
      isSubActive = true;
    } else if (user.subscription_active && user.expires_at <= now) {
      user.subscription_active = false;
      user.plan = 'free';
      await user.save();
    }

    return res.json({
      email: user.email,
      name: user.name,
      subscriptionActive: isSubActive,
      startedAt: isSubActive ? user.started_at : null,
      expiresAt: isSubActive ? user.expires_at : null,
      plan: user.plan,
      autoRenew: user.auto_renew !== false
    });
  } catch (err) {
    res.clearCookie('session_token');
    return res.status(401).json({ error: 'Invalid session' });
  }
});

app.post('/api/logout', (req, res) => {
  res.clearCookie('session_token', { sameSite: 'none', secure: true });
  res.json({ success: true });
});

app.post('/api/subscription/auto-renew', requireAuth, async (req, res) => {
  try {
    const { autoRenew } = req.body;
    await connectDB();
    if (!isConnected) return res.status(503).json({ error: 'Database unavailable' });
    await User.findOneAndUpdate({ email: req.userEmail }, { auto_renew: !!autoRenew });
    res.json({ success: true, autoRenew: !!autoRenew });
  } catch (err) {
    res.status(500).json({ error: 'Failed to update auto-renew' });
  }
});

// ==========================================
// 7. حذف الحساب
// ==========================================
app.post('/api/delete-account', requireAuth, async (req, res) => {
  try {
    await connectDB();
    if (isConnected) await User.findOneAndDelete({ email: req.userEmail });
    res.clearCookie('session_token', { sameSite: 'none', secure: true });
    res.json({ success: true, message: 'Account permanently deleted' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to delete account' });
  }
});

// ==========================================
// 8. الكوبونات
// ==========================================
app.post('/api/apply-coupon', requireAuth, async (req, res) => {
  const { couponCode } = req.body;
  if (!couponCode) return res.status(400).json({ error: 'No code provided' });
  const code = couponCode.trim().toUpperCase();

  try {
    await connectDB();
    if (!isConnected) return res.status(503).json({ error: 'قاعدة البيانات غير متصلة، حاول لاحقاً.' });

    const coupon = await Coupon.findOneAndUpdate(
      { code, active: true, $expr: { $lt: ['$usedCount', '$maxUses'] } },
      { $inc: { usedCount: 1 } },
      { new: true }
    );

    if (!coupon) return res.status(400).json({ error: 'الكود غير صحيح، أو اكتمل العدد المسموح.' });

    if (coupon.type === 'free') {
      const now = Date.now();
      const user = await User.findOne({ email: req.userEmail });
      const currentExpiry = (user?.subscription_active && user.expires_at > now) ? user.expires_at : now;
      await User.findOneAndUpdate(
        { email: req.userEmail },
        { subscription_active: true, plan: 'VIP_PRO', started_at: user?.started_at || now, expires_at: currentExpiry + 30 * DAY_MS, couponUsed: code },
        { upsert: true, new: true }
      );
      return res.json({ success: true, type: 'free' });
    }

    if (coupon.type === 'percent') return res.json({ type: 'percent', discount: coupon.discount });
  } catch (err) {
    res.status(500).json({ error: 'حدث خطأ في النظام' });
  }
});

app.get('/api/promo-stats', requireAuth, async (req, res) => {
  // تم تقييد هذا المسار بـ requireAuth الآن: الكود السري وترتيب المستخدم بيانات حساسة
  // ومفروض متتعرضش لأي زائر غير مسجل دخول
  try {
    await connectDB();
    if (!isConnected) return res.status(503).json({ error: 'Database unavailable' });

    let promo = await Coupon.findOne({ code: 'MOAZA2FREE' });
    if (!promo) promo = await Coupon.create({ code: 'MOAZA2FREE', type: 'free', maxUses: 15, usedCount: 0, active: true });

    const remaining = Math.max(0, promo.maxUses - promo.usedCount);
    res.json({ active: remaining > 0, remaining, currentRank: promo.usedCount + 1 });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ==========================================
// 9. تشغيل الأداة — Fail closed: أي شك أو انقطاع في القاعدة = منع الدخول، مش السماح
// ==========================================
app.get('/api/launch-app', requireAuth, async (req, res) => {
  try {
    await connectDB();
    if (!isConnected) {
      return res.status(503).send('<h1 style="text-align:center; margin-top:50px; font-family:sans-serif;">تعذّر التحقق من اشتراكك حالياً، حاول مرة أخرى خلال لحظات.</h1>');
    }
    const user = await User.findOne({ email: req.userEmail });
    if (!user || !user.subscription_active || user.expires_at < Date.now()) {
      return res.status(403).send('<h1 style="text-align:center; margin-top:50px; font-family:sans-serif;">عفواً، انتهى اشتراكك أو لم يتم تفعيله. يرجى الترقية لـ PRO.</h1>');
    }
    res.redirect(process.env.TOOL_URL || 'https://example.com');
  } catch (err) {
    res.status(500).send('خطأ في التحقق من الحساب.');
  }
});

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Artify Server running on port ${PORT}`);
});
module.exports = app;
