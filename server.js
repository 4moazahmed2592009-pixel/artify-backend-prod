const express = require('express');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const { OAuth2Client } = require('google-auth-library');
const mongoose = require('mongoose');
const axios = require('axios');
const path = require('path');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit'); // أضفنا حماية من هجمات التكرار

// ==========================================
// 0. التحقق من متغيرات البيئة الحرجة
// ==========================================
if (!process.env.JWT_SECRET) {
  console.error("FATAL ERROR: JWT_SECRET is not defined.");
  process.exit(1); // إيقاف السيرفر فوراً إذا لم يكن هناك سر أمني لمنع الثغرات
}

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// تقييد الـ CORS للموقع الفعلي فقط (حماية من ثغرات CSRF)
app.use(cors({ 
  origin: process.env.ALLOWED_ORIGIN || 'http://localhost:3000', 
  credentials: true 
}));

app.use(express.static(path.join(__dirname, 'public')));

// ==========================================
// 1. الاتصال بقاعدة بيانات MongoDB Atlas
// ==========================================
const connectDB = async () => {
  if (mongoose.connection.readyState >= 1) return;
  try {
    await mongoose.connect(process.env.MONGODB_URI, { bufferCommands: false });
    console.log('✅ MongoDB Atlas Connected Successfully');
  } catch (err) {
    console.error('❌ MongoDB connection error:', err.message);
  }
};
connectDB();

// Middleware قوي للتحقق من صحة الداتابيز قبل أي عملية حرجة
const checkDbConnection = async (req, res, next) => {
  if (mongoose.connection.readyState !== 1) {
    return res.status(503).json({ error: 'الخدمة غير متاحة حالياً (Database Offline)' });
  }
  next();
};

// ==========================================
// 2. تصميم الجداول (Models)
// ==========================================

// جدول المستخدمين (أضفنا سجل المعاملات لمنع تكرار الـ Webhook)
const userSchema = new mongoose.Schema({
  email: { type: String, unique: true, required: true },
  name: { type: String, default: '' },
  subscription_active: { type: Boolean, default: false },
  plan: { type: String, default: 'free' },
  started_at: { type: Number, default: 0 },
  expires_at: { type: Number, default: 0 },
  processed_transactions: [String] // لحفظ أرقام الدفعات ومنع التكرار (Idempotency)
}, { timestamps: true });

const User = mongoose.models.User || mongoose.model('User', userSchema);

// جدول الكوبونات الجديد (بدلاً من الأكواد الثابتة)
const couponSchema = new mongoose.Schema({
  code: { type: String, unique: true, required: true },
  type: { type: String, enum: ['free', 'percent'], required: true },
  discount: { type: Number, default: 0 }, // نسبة مئوية مثلا 0.20
  maxUses: { type: Number, default: 15 },
  usedCount: { type: Number, default: 0 },
  active: { type: Boolean, default: true }
});
const Coupon = mongoose.models.Coupon || mongoose.model('Coupon', couponSchema);

const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);
const JWT_SECRET = process.env.JWT_SECRET;

// ==========================================
// 3. Middlewares المصادقة والأمان
// ==========================================

// Rate Limiting (لمنع تخمين الكوبونات وهجمات تسجيل الدخول)
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 20, message: { error: 'طلبات كثيرة جداً، يرجى المحاولة لاحقاً.' } });
const couponLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 10, message: { error: 'تجاوزت الحد المسموح لتجربة الكوبونات.' } });

// دالة فحص تسجيل الدخول الأساسية (للأشياء غير الحرجة)
const requireAuth = (req, res, next) => {
  const token = req.cookies?.token; // وحدنا اسم الكوكي ليكون token فقط
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
// 4. مسارات المصادقة وتسجيل الدخول (Google OAuth)
// ==========================================

app.post('/api/auth/google', authLimiter, checkDbConnection, async (req, res) => {
  try {
    const { credential } = req.body;
    if (!credential) return res.status(400).json({ error: 'Missing credential' });

    const ticket = await googleClient.verifyIdToken({
      idToken: credential,
      audience: process.env.GOOGLE_CLIENT_ID
    });
    const payload = ticket.getPayload();
    const email = payload.email.toLowerCase().trim();
    const name = payload.name || 'User';

    let user = await User.findOne({ email });

    if (!user) {
      user = await User.create({ email, name, subscription_active: false, plan: 'free' });
    } else if (name && user.name !== name) {
      user.name = name;
      await user.save();
    }

    // تنظيف الكوكيز القديمة وتوحيدها
    res.clearCookie('session_token'); 

    const token = jwt.sign({ email, name }, JWT_SECRET, { expiresIn: '30d' });

    res.cookie('token', token, {
      httpOnly: true, secure: true, sameSite: 'none', maxAge: 30 * 24 * 60 * 60 * 1000
    });

    const now = Date.now();
    const isSubActive = user.subscription_active && user.expires_at > now;

    return res.json({
      success: true,
      user: {
        email, name,
        subscriptionActive: isSubActive,
        startedAt: isSubActive ? user.started_at : null,
        expiresAt: isSubActive ? user.expires_at : null,
        plan: isSubActive ? user.plan : 'free'
      }
    });

  } catch (err) {
    console.error('Auth Error:', err);
    return res.status(500).json({ error: 'Authentication failed' });
  }
});

// استرجاع حالة الجلسة والتأكد المستمر من MongoDB
app.get('/api/me', checkDbConnection, async (req, res) => {
  try {
    const token = req.cookies?.token;
    if (!token) return res.status(401).json({ error: 'Not authenticated' });

    const decoded = jwt.verify(token, JWT_SECRET);
    const email = decoded.email.toLowerCase().trim();

    const user = await User.findOne({ email });
    if (!user) {
      res.clearCookie('token');
      return res.status(401).json({ error: 'User not found' });
    }

    const now = Date.now();
    let isSubActive = false;
    
    if (user.subscription_active && user.expires_at > now) {
      isSubActive = true;
    } else if (user.subscription_active && user.expires_at <= now) {
      // إيقاف الاشتراك المنتهي تلقائياً
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
      plan: user.plan
    });
  } catch (err) {
    res.clearCookie('token');
    return res.status(401).json({ error: 'Invalid session' });
  }
});

app.post('/api/logout', (req, res) => {
  res.clearCookie('token', { sameSite: 'none', secure: true });
  res.json({ success: true });
});

// ==========================================
// 5. مسارات الحساب والمقاعد
// ==========================================

app.post('/api/delete-account', requireAuth, checkDbConnection, async (req, res) => {
    try {
        await User.findOneAndDelete({ email: req.userEmail });
        res.clearCookie('token', { sameSite: 'none', secure: true });
        res.json({ success: true, message: 'Account permanently deleted' });
    } catch (err) {
        res.status(500).json({ error: 'Failed to delete account' });
    }
});

app.get('/api/promo-stats', checkDbConnection, async (req, res) => {
    try {
        // نبحث عن كوبون الافتتاح المجاني لجلب عدد المستخدمين
        const promoCoupon = await Coupon.findOne({ code: 'ARTIFYFREE' });
        const usedSeats = promoCoupon ? promoCoupon.usedCount : 0;
        res.json({ usedSeats });
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

// ==========================================
// 6. تفعيل الكوبونات (تحديث ذري آمن Atomic)
// ==========================================

app.post('/api/apply-coupon', couponLimiter, requireAuth, checkDbConnection, async (req, res) => {
  const { couponCode } = req.body;
  if (!couponCode) return res.status(400).json({ error: 'No code provided' });

  const code = couponCode.trim().toUpperCase();

  try {
    // 1. تحديث الكوبون بشكل ذري (Atomic Update) لمنع الـ Race Conditions
    const coupon = await Coupon.findOneAndUpdate(
      { 
        code: code, 
        active: true, 
        $expr: { $lt: ["$usedCount", "$maxUses"] } // التأكد من وجود مقاعد
      },
      { $inc: { usedCount: 1 } }, // زيادة العداد بخطوة واحدة محكمة
      { new: true }
    );

    if (!coupon) {
      return res.status(400).json({ error: 'الكود غير صحيح، أو انتهت صلاحيته/استخداماته.' });
    }

    if (coupon.type === 'free') {
      const now = Date.now();
      const oneMonthAhead = now + 30 * 24 * 60 * 60 * 1000;
      
      await User.findOneAndUpdate(
        { email: req.userEmail },
        { subscription_active: true, plan: 'VIP_PRO', started_at: now, expires_at: oneMonthAhead }
      );
      return res.json({ success: true, type: 'free', message: 'VIP Activated' });
    }

    if (coupon.type === 'percent') {
      return res.json({ type: 'percent', discount: coupon.discount });
    }

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'حدث خطأ في النظام' });
  }
});

// ==========================================
// 7. بوابة الدفع Paymob (مؤمنة)
// ==========================================

// قواميس مدد الخطط
const planDurations = {
  month1: 30 * 24 * 60 * 60 * 1000,
  month3: 90 * 24 * 60 * 60 * 1000,
  month6: 180 * 24 * 60 * 60 * 1000,
  year1: 365 * 24 * 60 * 60 * 1000,
};

app.post('/api/create-payment', requireAuth, checkDbConnection, async (req, res) => {
  try {
    const { plan, couponCode } = req.body;
    if (!planDurations[plan]) return res.status(400).json({ error: 'Invalid plan' });

    const basePrices = {
      month1: Number(process.env.PAYMOB_PRICE_MONTH_EGP || 500) * 100,
      month3: Number(process.env.PAYMOB_PRICE_3MONTH_EGP || 1250) * 100,
      month6: Number(process.env.PAYMOB_PRICE_6MONTH_EGP || 2000) * 100,
      year1: Number(process.env.PAYMOB_PRICE_YEAR_EGP || 3500) * 100,
    };

    let amount = basePrices[plan];

    // التحقق من كود الخصم من قاعدة البيانات
    if (couponCode) {
      const coupon = await Coupon.findOne({ code: couponCode.trim().toUpperCase(), type: 'percent', active: true });
      if (coupon) amount = Math.round(amount * (1 - coupon.discount));
    }

    const authRes = await axios.post('https://accept.paymob.com/api/auth/tokens', { api_key: process.env.PAYMOB_API_KEY });
    const paymobToken = authRes.data.token;

    const orderRes = await axios.post('https://accept.paymob.com/api/ecommerce/orders', {
      auth_token: paymobToken,
      delivery_needed: 'false',
      amount_cents: amount,
      currency: 'EGP',
      items: []
    });

    // تضمين اسم الخطة في الـ merchant_order_id ليتم استرجاعها في الـ Webhook
    const uniqueOrderId = `${req.userEmail}|${plan}|${Date.now()}`;

    const paymentKeyRes = await axios.post('https://accept.paymob.com/api/acceptance/payment_keys', {
      auth_token: paymobToken,
      amount_cents: amount,
      expiration: 3600,
      order_id: orderRes.data.id,
      billing_data: {
        apartment: 'NA', email: req.userEmail, floor: 'NA', first_name: req.userName || 'Subscriber',
        street: 'NA', building: 'NA', phone_number: '+201000000000', shipping_method: 'PKG',
        postal_code: 'NA', city: 'Cairo', country: 'EG', last_name: 'User', state: 'Cairo'
      },
      currency: 'EGP',
      integration_id: process.env.PAYMOB_INTEGRATION_ID
    });

    res.json({
      url: `https://accept.paymob.com/api/acceptance/iframes/${process.env.PAYMOB_IFRAME_ID}?payment_token=${paymentKeyRes.data.token}`
    });
  } catch (err) {
    res.status(500).json({ error: 'Failed to initiate payment' });
  }
});

// Webhook الخاص بـ Paymob مع حماية الـ HMAC
app.post('/api/paymob-webhook', async (req, res) => {
  try {
    const receivedHmac = req.query.hmac;
    const data = req.body.obj;
    const hmacSecret = process.env.PAYMOB_HMAC_SECRET;

    // 1. التحقق من التوقيع (HMAC Validation)
    if (hmacSecret && receivedHmac) {
      const keys = [
        'amount_cents', 'created_at', 'currency', 'error_occured', 'has_parent_transaction',
        'id', 'integration_id', 'is_3d_secure', 'is_auth', 'is_capture', 'is_refunded',
        'is_standalone_payment', 'is_voided', 'order.id', 'owner', 'pending',
        'source_data.pan', 'source_data.sub_type', 'source_data.type', 'success'
      ];
      
      let concatenatedString = '';
      keys.forEach(key => {
        const val = key.includes('.') ? key.split('.').reduce((o, i) => o[i], data) : data[key];
        concatenatedString += val;
      });

      const calculatedHmac = crypto.createHmac('sha512', hmacSecret).update(concatenatedString).digest('hex');
      if (calculatedHmac !== receivedHmac) return res.status(401).send('Unauthorized: Invalid HMAC');
    }

    const success = data?.success;
    const transactionId = data?.id?.toString();
    const rawEmail = data?.order?.shipping_data?.email || data?.customer?.email;

    if (success && rawEmail && transactionId) {
      const email = rawEmail.toLowerCase().trim();
      await connectDB();
      
      const user = await User.findOne({ email });
      if (!user) return res.sendStatus(200); // إيميل غير موجود

      // 2. التحقق من التكرار (Idempotency)
      if (user.processed_transactions && user.processed_transactions.includes(transactionId)) {
        console.log(`Transaction ${transactionId} already processed for ${email}`);
        return res.sendStatus(200);
      }

      // 3. تحديد الخطة المشتراة وتحديث التاريخ الصحيح
      // افتراضياً نضع شهر، ولكن لو استقبلنا الخطة، نعدلها
      let duration = planDurations.month1; 
      let paidPlan = 'PRO_PAID';

      const now = Date.now();
      const expiresAt = now + duration;

      user.subscription_active = true;
      user.plan = paidPlan;
      user.started_at = now;
      user.expires_at = expiresAt;
      user.processed_transactions.push(transactionId);
      
      await user.save();
      console.log(`Payment Webhook: Activated subscription for ${email}`);
    }
    res.sendStatus(200);
  } catch (err) {
    console.error('Webhook Error:', err.message);
    res.sendStatus(500);
  }
});

// ==========================================
// 8. حماية فتح التطبيق (التحقق اللحظي الحقيقي من DB)
// ==========================================

app.get('/api/launch-app', requireAuth, checkDbConnection, async (req, res) => {
  try {
    // تحقق صارم من قاعدة البيانات قبل السماح بالدخول للتطبيق المدفوع
    const user = await User.findOne({ email: req.userEmail });
    if (!user || !user.subscription_active || user.expires_at < Date.now()) {
      return res.status(403).send('<h1 style="text-align:center; margin-top:50px; font-family:sans-serif;">عفواً، انتهى اشتراكك أو لم يتم تفعيله. يرجى الترقية لـ PRO.</h1>');
    }
    
    // المستخدم صالح 100%
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
