const express = require('express');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit'); // npm i express-rate-limit
const { OAuth2Client } = require('google-auth-library');
const mongoose = require('mongoose');
const axios = require('axios');
const path = require('path');

const app = express();

// ==========================================
// 0. التحقق من متغيرات البيئة الحرجة عند الإقلاع
//    (إصلاح: JWT_SECRET كانت له قيمة افتراضية مكتوبة في الكود، وده خطر
//    لأن أي شخص يشوف الكود المصدري يقدر يزوّر توكنات كاملة. الآن السيرفر
//    يرفض يبدأ أصلاً لو المتغيرات دي غير موجودة.)
// ==========================================
const REQUIRED_ENV = ['MONGODB_URI', 'JWT_SECRET', 'GOOGLE_CLIENT_ID'];
const missingEnv = REQUIRED_ENV.filter((k) => !process.env[k]);
if (missingEnv.length > 0) {
  console.error(`FATAL: Missing required environment variables: ${missingEnv.join(', ')}`);
  process.exit(1);
}

const JWT_SECRET = process.env.JWT_SECRET;
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || null; // مثال: https://artify.example.com
const MAX_FREE_SEATS = Number(process.env.MAX_FREE_SEATS || 15);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// ==========================================
// إصلاح CORS: كان مفتوح بالكامل (origin: true) وده يسمح لأي موقع يبعت
// طلبات معتمدة (بالكوكيز) لسيرفرك. الآن مقفول على الدومين الحقيقي بس.
// ==========================================
app.use(
  cors({
    origin: ALLOWED_ORIGIN || false, // لو المتغير غير موجود، اقفل CORS تماماً بدل فتحه
    credentials: true,
  })
);

app.use(express.static(path.join(__dirname, 'public')));

// ==========================================
// 1. الاتصال بقاعدة بيانات MongoDB Atlas
//    (إصلاح: كان الاتصال بيتم من غير await حقيقي، وأي مسار حساس كان
//    بيكمل "بنجاح" حتى لو الاتصال فاشل. الآن نعتمد على mongoose.connection.readyState
//    مباشرة كمصدر وحيد للحقيقة، ومفيش أي مسار حساس يكمل لو الاتصال غير جاهز.)
// ==========================================
async function connectDB() {
  if (mongoose.connection.readyState === 1) return;
  try {
    await mongoose.connect(process.env.MONGODB_URI, { bufferCommands: false });
    console.log('MongoDB Atlas Connected Successfully');
  } catch (err) {
    console.error('MongoDB connection FAILED:', err.message);
  }
}
connectDB();

mongoose.connection.on('disconnected', () => console.warn('MongoDB disconnected'));
mongoose.connection.on('reconnected', () => console.log('MongoDB reconnected'));
mongoose.connection.on('error', (err) => console.error('MongoDB error:', err.message));

// Middleware: يرفض أي مسار حساس لو قاعدة البيانات غير متصلة فعلياً،
// بدل ما "ينجح" العملية شكلياً من غير أي أثر مسجل (كان هذا سبب ثبات عداد المقاعد).
function requireDbConnected(req, res, next) {
  if (mongoose.connection.readyState !== 1) {
    return res.status(503).json({ error: 'Service temporarily unavailable, please try again shortly' });
  }
  next();
}

// ==========================================
// نماذج قاعدة البيانات (Models)
// ==========================================

// جدول المستخدمين
const userSchema = new mongoose.Schema(
  {
    email: { type: String, unique: true, required: true },
    name: { type: String, default: '' },
    subscription_active: { type: Boolean, default: false },
    plan: { type: String, default: 'free' },
    started_at: { type: Number, default: 0 },
    expires_at: { type: Number, default: 0 },
    couponUsed: { type: String, default: '' },
  },
  { timestamps: true }
);
const User = mongoose.models.User || mongoose.model('User', userSchema);

// إصلاح: الكوبونات كانت مكتوبة Hardcoded في الكود (DISCOUNT20, SAVE50, VIP2026).
// الآن الكوبونات في قاعدة البيانات، قابلة للإدارة بدون تعديل كود أو إعادة نشر.
const couponSchema = new mongoose.Schema(
  {
    code: { type: String, unique: true, required: true, uppercase: true, trim: true },
    type: { type: String, enum: ['free', 'percent'], required: true },
    discount: { type: Number, default: 0 }, // مستخدم فقط لو type === 'percent' (مثال: 0.2 = 20%)
    active: { type: Boolean, default: true },
    maxUses: { type: Number, default: null }, // null = بلا حد أقصى
    usedCount: { type: Number, default: 0 },
    expiresAt: { type: Number, default: null }, // timestamp، null = بلا انتهاء
  },
  { timestamps: true }
);
const Coupon = mongoose.models.Coupon || mongoose.model('Coupon', couponSchema);

// إصلاح: كان الـ webhook بياخد الإيميل والخطة من نفس رسالة الـ webhook (غير موثوقة).
// الآن نخزن كل عملية دفع تم إنشاؤها في create-payment (order id + email + plan)،
// وفي الـ webhook نرجع لهذا السجل بدل ما نثق في بيانات الـ webhook مباشرة.
// كمان يُستخدم لمنع معالجة نفس العملية مرتين (Idempotency).
const pendingOrderSchema = new mongoose.Schema(
  {
    paymobOrderId: { type: Number, unique: true, required: true },
    email: { type: String, required: true },
    plan: { type: String, required: true },
    couponCode: { type: String, default: '' },
    status: { type: String, enum: ['pending', 'processed', 'failed'], default: 'pending' },
    processedTransactionId: { type: String, default: '' },
  },
  { timestamps: true }
);
const PendingOrder = mongoose.models.PendingOrder || mongoose.model('PendingOrder', pendingOrderSchema);

const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

// ==========================================
// Rate limiting على المسارات الحساسة
// (إصلاح: مفيش كان حماية من محاولات متكررة على تسجيل الدخول أو الكوبونات)
// ==========================================
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many attempts, please try again later' },
});

const couponLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many attempts, please try again later' },
});

// مدة كل خطة بالمللي ثانية — تُستخدم لحساب expires_at الصحيح
// (إصلاح: كان الـ webhook دايماً بيحسب 30 يوم ثابت بغض النظر عن الخطة المدفوعة فعلياً)
const PLAN_DURATIONS_MS = {
  month1: 30 * 24 * 60 * 60 * 1000,
  month3: 90 * 24 * 60 * 60 * 1000,
  month6: 180 * 24 * 60 * 60 * 1000,
  year1: 365 * 24 * 60 * 60 * 1000,
};

// دالة فحص تسجيل الدخول — تحدد هوية المستخدم من التوكن فقط (بدون حالة الاشتراك)
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

// ==========================================
// إصلاح جوهري: التحقق من الاشتراك كان يعتمد على بيانات التوكن (JWT) اللي
// صالحة 30 يوم، يعني لو الاشتراك انتهى أو اتلغى من قاعدة البيانات، المستخدم
// كان يفضل يقدر يفتح الأداة المدفوعة لغاية ما التوكن نفسه ينتهي.
// الآن هذا الـ middleware يتحقق لحظياً من قاعدة البيانات مباشرة، مش من التوكن.
// ==========================================
const requireActiveSubscriptionFresh = async (req, res, next) => {
  try {
    const user = await User.findOne({ email: req.userEmail });
    const now = Date.now();
    const isActive = !!(user && user.subscription_active && user.expires_at && Number(user.expires_at) > now);
    if (!isActive) {
      return res.status(403).json({ error: 'Active subscription required' });
    }
    req.freshUser = user;
    next();
  } catch (err) {
    return res.status(503).json({ error: 'Could not verify subscription, try again shortly' });
  }
};

function setSessionCookie(res, token) {
  res.cookie('session_token', token, {
    httpOnly: true,
    secure: true,
    sameSite: 'none',
    maxAge: 7 * 24 * 60 * 60 * 1000, // تم تقليلها من 30 يوم إلى 7 أيام لتقليل نافذة بيانات قديمة داخل التوكن
  });
}

function clearSessionCookies(res) {
  res.clearCookie('session_token', { sameSite: 'none', secure: true });
  // تنظيف الكوكي القديم المكرر من الإصدار السابق من الكود
  res.clearCookie('token', { sameSite: 'none', secure: true });
}

// ==========================================
// 2. مسارات المصادقة وتسجيل الدخول (Google OAuth)
// ==========================================

app.post('/api/auth/google', authLimiter, requireDbConnected, async (req, res) => {
  try {
    const { credential } = req.body;
    if (!credential) return res.status(400).json({ error: 'Missing credential' });

    const ticket = await googleClient.verifyIdToken({
      idToken: credential,
      audience: process.env.GOOGLE_CLIENT_ID,
    });
    const payload = ticket.getPayload();
    const email = payload.email.toLowerCase().trim();
    const name = payload.name || 'User';

    let user = await User.findOne({ email });
    if (!user) {
      user = await User.create({
        email,
        name,
        subscription_active: false,
        plan: 'free',
        started_at: 0,
        expires_at: 0,
      });
      console.log('New user created in MongoDB:', email);
    } else if (name && user.name !== name) {
      user.name = name;
      await user.save();
    }

    // التوكن الآن يحمل الهوية فقط، بدون حالة اشتراك (تُقرأ دايماً من قاعدة البيانات لحظياً)
    const token = jwt.sign({ email, name }, JWT_SECRET, { expiresIn: '7d' });
    setSessionCookie(res, token);

    const now = Date.now();
    const isSubActive = !!(user.subscription_active && user.expires_at && Number(user.expires_at) > now);

    return res.json({
      success: true,
      user: {
        email,
        name,
        subscriptionActive: isSubActive,
        startedAt: isSubActive ? Number(user.started_at) : null,
        expiresAt: isSubActive ? Number(user.expires_at) : null,
        plan: isSubActive ? user.plan : 'free',
      },
    });
  } catch (err) {
    console.error('Google Auth Error:', err);
    return res.status(500).json({ error: 'Authentication failed' });
  }
});

app.get('/api/me', requireAuth, requireDbConnected, async (req, res) => {
  try {
    const user = await User.findOne({ email: req.userEmail });
    if (!user) return res.status(404).json({ error: 'User not found' });

    const now = Date.now();
    const isSubActive = !!(user.subscription_active && user.expires_at && Number(user.expires_at) > now);

    return res.json({
      email: user.email,
      name: req.userName,
      subscriptionActive: isSubActive,
      startedAt: isSubActive ? Number(user.started_at) : null,
      expiresAt: isSubActive ? Number(user.expires_at) : null,
      plan: isSubActive ? user.plan : 'free',
    });
  } catch (err) {
    return res.status(503).json({ error: 'Could not fetch profile, try again shortly' });
  }
});

app.post('/api/logout', (req, res) => {
  clearSessionCookies(res);
  res.json({ success: true });
});

// ==========================================
// 3. مسارات النظام والحساب (System & Account)
// ==========================================

app.post('/api/delete-account', requireAuth, requireDbConnected, async (req, res) => {
  try {
    await User.findOneAndDelete({ email: req.userEmail });
    clearSessionCookies(res);
    res.json({ success: true, message: 'Account permanently deleted' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to delete account' });
  }
});

// إصلاح: كان بيرجع usedSeats: 0 بشكل صامت لو قاعدة البيانات غير متصلة،
// وده سبب ثبات عداد "15 مقعد" بشكل دائم. الآن يرجع خطأ واضح 503 بدل قيمة مضللة.
app.get('/api/promo-stats', requireDbConnected, async (req, res) => {
  try {
    const counter = await getOrCreatePromoCounter();
    const usedSeats = counter.count;
    res.json({ usedSeats, maxSeats: MAX_FREE_SEATS });
  } catch (err) {
    res.status(503).json({ error: 'Could not fetch promo stats' });
  }
});

// ==========================================
// 4. تفعيل الكوبونات وتثبيت الاشتراك
// ==========================================

// عداد ذرّي (Atomic) لاستخدامات كوبون المقاعد المجانية — يمنع Race Condition
// حتى لو جاء طلبان في نفس اللحظة تماماً (بدلاً من countDocuments على جدول المستخدمين
// اللي كان عرضة لتزاحم قراءة/كتابة منفصلة).
const promoCounterSchema = new mongoose.Schema({
  key: { type: String, unique: true, required: true },
  count: { type: Number, default: 0 },
});
const PromoCounter = mongoose.models.PromoCounter || mongoose.model('PromoCounter', promoCounterSchema);

async function getOrCreatePromoCounter() {
  let counter = await PromoCounter.findOne({ key: 'ARTIFYFREE' });
  if (!counter) {
    counter = await PromoCounter.findOneAndUpdate(
      { key: 'ARTIFYFREE' },
      { $setOnInsert: { count: 0 } },
      { upsert: true, new: true }
    );
  }
  return counter;
}

// يحاول "حجز" مقعد مجاني بشكل ذرّي؛ يرجع true لو نجح الحجز، false لو المقاعد خلصت
async function tryReserveFreeSeatAtomic() {
  const result = await PromoCounter.findOneAndUpdate(
    { key: 'ARTIFYFREE', count: { $lt: MAX_FREE_SEATS } },
    { $inc: { count: 1 } },
    { new: true }
  );
  return !!result;
}

app.post('/api/apply-coupon', requireAuth, requireDbConnected, couponLimiter, async (req, res) => {
  const { couponCode } = req.body;
  if (!couponCode) return res.status(400).json({ error: 'No code provided' });

  const code = couponCode.trim().toUpperCase();
  const email = req.userEmail.toLowerCase().trim();

  try {
    const coupon = await Coupon.findOne({ code });
    if (!coupon || !coupon.active) {
      return res.status(400).json({ error: 'كود خصم غير صالح' });
    }
    if (coupon.expiresAt && Date.now() > coupon.expiresAt) {
      return res.status(400).json({ error: 'انتهت صلاحية هذا الكود' });
    }
    if (coupon.maxUses !== null && coupon.usedCount >= coupon.maxUses) {
      return res.status(400).json({ error: 'تم استهلاك هذا الكود بالكامل' });
    }

    if (coupon.type === 'free') {
      const user = await User.findOne({ email });

      // لو المستخدم استخدم نفس الكوبون قبل كده، رجّع له حالة اشتراكه الحالية
      // بدون حجز مقعد جديد (Idempotent) بدل ما يستهلك مقعد إضافي بالخطأ.
      if (user && user.couponUsed === code && user.subscription_active) {
        return res.json({ success: true, type: 'free', message: 'Already activated', expiresAt: user.expires_at });
      }

      // حجز مقعد بشكل ذرّي فقط لكوبونات المقاعد المحدودة (maxUses محدد)
      if (coupon.maxUses !== null) {
        const reserved = await tryReserveFreeSeatAtomic();
        if (!reserved) {
          return res.status(400).json({ error: 'اكتمل عدد المقاعد المجانية!' });
        }
      }

      const now = Date.now();
      const oneMonthAhead = now + PLAN_DURATIONS_MS.month1;

      await User.findOneAndUpdate(
        { email },
        {
          subscription_active: true,
          plan: 'VIP_PRO',
          started_at: now,
          expires_at: oneMonthAhead,
          couponUsed: code,
        },
        { upsert: true, new: true }
      );

      await Coupon.updateOne({ code }, { $inc: { usedCount: 1 } });

      return res.json({ success: true, type: 'free', message: 'VIP Activated', expiresAt: oneMonthAhead });
    }

    if (coupon.type === 'percent') {
      await Coupon.updateOne({ code }, { $inc: { usedCount: 1 } });
      return res.json({ type: 'percent', discount: coupon.discount });
    }

    return res.status(400).json({ error: 'كود خصم غير صالح' });
  } catch (err) {
    console.error('Apply coupon error:', err.message);
    return res.status(500).json({ error: 'Server error, please try again' });
  }
});

// ==========================================
// 5. بوابة الدفع Paymob
// ==========================================

app.post('/api/create-payment', requireAuth, requireDbConnected, async (req, res) => {
  try {
    const { plan, couponCode } = req.body;
    if (!PLAN_DURATIONS_MS[plan]) {
      return res.status(400).json({ error: 'Invalid plan' });
    }

    const basePrices = {
      month1: Number(process.env.PAYMOB_PRICE_MONTH_EGP || 500) * 100,
      month3: Number(process.env.PAYMOB_PRICE_3MONTH_EGP || 1250) * 100,
      month6: Number(process.env.PAYMOB_PRICE_6MONTH_EGP || 2000) * 100,
      year1: Number(process.env.PAYMOB_PRICE_YEAR_EGP || 3500) * 100,
    };

    let amount = basePrices[plan];
    let appliedCouponCode = '';

    // التحقق من كود الخصم من قاعدة البيانات (بدل if ثابتة على أكواد مكتوبة في الكود)
    if (couponCode) {
      const coupon = await Coupon.findOne({ code: couponCode.trim().toUpperCase(), type: 'percent', active: true });
      if (coupon) {
        amount = Math.round(amount * (1 - coupon.discount));
        appliedCouponCode = coupon.code;
      }
    }

    const authRes = await axios.post('https://accept.paymob.com/api/auth/tokens', {
      api_key: process.env.PAYMOB_API_KEY,
    });
    const paymobToken = authRes.data.token;

    const orderRes = await axios.post('https://accept.paymob.com/api/ecommerce/orders', {
      auth_token: paymobToken,
      delivery_needed: 'false',
      amount_cents: amount,
      currency: 'EGP',
      items: [],
    });

    const paymobOrderId = orderRes.data.id;

    // إصلاح: نخزن ربط (order id -> email + الخطة الحقيقية) بدل الاعتماد على بيانات
    // الـ webhook نفسها لتحديد الخطة، وهذا أيضاً يمنّع معالجة نفس الطلب مرتين لاحقاً.
    await PendingOrder.create({
      paymobOrderId,
      email: req.userEmail.toLowerCase().trim(),
      plan,
      couponCode: appliedCouponCode,
      status: 'pending',
    });

    const paymentKeyRes = await axios.post('https://accept.paymob.com/api/acceptance/payment_keys', {
      auth_token: paymobToken,
      amount_cents: amount,
      expiration: 3600,
      order_id: paymobOrderId,
      billing_data: {
        apartment: 'NA',
        email: req.userEmail,
        floor: 'NA',
        first_name: req.userName || 'Subscriber',
        street: 'NA',
        building: 'NA',
        phone_number: '+201000000000',
        shipping_method: 'PKG',
        postal_code: 'NA',
        city: 'Cairo',
        country: 'EG',
        last_name: 'User',
        state: 'Cairo',
      },
      currency: 'EGP',
      integration_id: process.env.PAYMOB_INTEGRATION_ID,
    });

    res.json({
      url: `https://accept.paymob.com/api/acceptance/iframes/${process.env.PAYMOB_IFRAME_ID}?payment_token=${paymentKeyRes.data.token}`,
    });
  } catch (err) {
    console.error('Paymob Error:', err.response?.data || err.message);
    res.status(500).json({ error: 'Failed to initiate payment' });
  }
});

// ==========================================
// إصلاح جوهري: التحقق من توقيع HMAC الخاص بـ Paymob
// كان الـ webhook قبل ذلك يقبل أي طلب POST وارد ويفعّل اشتراك مباشرة، وهذا يسمح
// لأي طرف خارجي بتزوير طلب "دفع ناجح" بدون أي دفع فعلي. الآن نتحقق من HMAC
// المرسل في query string (?hmac=...) قبل معالجة أي بيانات من الطلب.
// ترتيب الحقول هنا مطابق لتوثيق Paymob الرسمي لـ Transaction Processed Callback.
// ==========================================
function verifyPaymobHmac(obj, receivedHmac) {
  const hmacSecret = process.env.PAYMOB_HMAC_SECRET;
  if (!hmacSecret || !receivedHmac) return false;

  const orderedFields = [
    'amount_cents',
    'created_at',
    'currency',
    'error_occured',
    'has_parent_transaction',
    'id',
    'integration_id',
    'is_3d_secure',
    'is_auth',
    'is_capture',
    'is_refunded',
    'is_standalone_payment',
    'is_voided',
    'order.id',
    'owner',
    'pending',
    'source_data.pan',
    'source_data.sub_type',
    'source_data.type',
    'success',
  ];

  const getValue = (path) => {
    const parts = path.split('.');
    let val = obj;
    for (const p of parts) {
      val = val ? val[p] : undefined;
    }
    return val === undefined || val === null ? '' : String(val);
  };

  const concatenated = orderedFields.map(getValue).join('');
  const computedHmac = crypto.createHmac('sha512', hmacSecret).update(concatenated).digest('hex');

  try {
    return crypto.timingSafeEqual(Buffer.from(computedHmac, 'utf8'), Buffer.from(receivedHmac, 'utf8'));
  } catch {
    return false; // اختلاف الطول بين المقارنتين يعني عدم تطابق
  }
}

app.post('/api/paymob-webhook', requireDbConnected, async (req, res) => {
  try {
    const obj = req.body.obj;
    const receivedHmac = req.query.hmac;

    if (!obj || !verifyPaymobHmac(obj, receivedHmac)) {
      console.warn('Paymob webhook: HMAC verification failed — request rejected');
      return res.sendStatus(401);
    }

    const success = obj.success;
    const transactionId = String(obj.id || '');
    const paymobOrderId = obj.order?.id;

    if (!success || !paymobOrderId) {
      return res.sendStatus(200); // نرد 200 لتجنب إعادة محاولات Paymob على معاملات فاشلة أصلاً
    }

    // إصلاح Idempotency: لو المعاملة دي اتعالجت قبل كده، تجاهلها تماماً
    const pendingOrder = await PendingOrder.findOne({ paymobOrderId });
    if (!pendingOrder) {
      console.warn(`Paymob webhook: no matching pending order for id ${paymobOrderId}`);
      return res.sendStatus(200);
    }
    if (pendingOrder.status === 'processed') {
      return res.sendStatus(200); // معالجة مسبقاً — تجاهل الإشعار المكرر
    }

    // إصلاح: مدة الاشتراك الآن تُحسب حسب الخطة الحقيقية المخزنة من create-payment
    // بدل قيمة ثابتة 30 يوم دايماً بغض النظر عن الخطة المدفوعة.
    const durationMs = PLAN_DURATIONS_MS[pendingOrder.plan] || PLAN_DURATIONS_MS.month1;
    const now = Date.now();
    const expiresAt = now + durationMs;

    await User.findOneAndUpdate(
      { email: pendingOrder.email },
      { subscription_active: true, plan: 'PRO_PAID', started_at: now, expires_at: expiresAt },
      { upsert: true }
    );

    pendingOrder.status = 'processed';
    pendingOrder.processedTransactionId = transactionId;
    await pendingOrder.save();

    console.log(`Payment Webhook: Activated ${pendingOrder.plan} subscription for ${pendingOrder.email}`);
    res.sendStatus(200);
  } catch (err) {
    console.error('Webhook Error:', err.message);
    res.sendStatus(500);
  }
});

// ==========================================
// 6. حماية فتح التطبيق والواجهة
// ==========================================

// إصلاح: كان بيتحقق من isSubActive المخزنة داخل التوكن (قديمة حتى 30 يوم).
// الآن يستخدم requireActiveSubscriptionFresh اللي يسأل قاعدة البيانات مباشرة.
app.get('/api/launch-app', requireAuth, requireDbConnected, requireActiveSubscriptionFresh, (req, res) => {
  res.redirect(process.env.TOOL_URL || 'https://example.com');
});

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Artify Server running on port ${PORT}`);
});

module.exports = app;
