const express = require('express');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const { OAuth2Client } = require('google-auth-library');
const mongoose = require('mongoose');
const axios = require('axios');
const path = require('path');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

app.use(cors({ origin: true, credentials: true }));
app.use(express.static(path.join(__dirname, 'public')));

// ==========================================
// 1. الأمان والاتصال بقاعدة البيانات
// ==========================================
// وضعنا المفاتيح الافتراضية حتى لا ينهار السيرفر إذا نسيتها في Vercel
const JWT_SECRET = process.env.JWT_SECRET || 'artify_fallback_secret_key_2026';
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || '1054667161687-q2gipahtngpfqfh9aj0q3jm55ajk257o.apps.googleusercontent.com';
const googleClient = new OAuth2Client(GOOGLE_CLIENT_ID);

let isConnected = false;
const connectDB = async () => {
  if (isConnected) return;
  if (!process.env.MONGODB_URI) {
      console.warn("⚠️ رابط MONGODB_URI غير موجود في إعدادات Vercel.");
      return;
  }
  try {
    // وضعنا مهلة 5 ثواني لكي لا ينهار Vercel إذا تأخرت الداتابيز
    await mongoose.connect(process.env.MONGODB_URI, { serverSelectionTimeoutMS: 5000 });
    isConnected = true;
    console.log('✅ MongoDB Connected');
  } catch (err) {
    console.error('❌ MongoDB error:', err.message);
  }
};

// ==========================================
// 2. الجداول (Models)
// ==========================================
const userSchema = new mongoose.Schema({
  email: { type: String, unique: true, required: true },
  name: { type: String, default: '' },
  subscription_active: { type: Boolean, default: false },
  plan: { type: String, default: 'free' },
  started_at: { type: Number, default: 0 },
  expires_at: { type: Number, default: 0 },
  couponUsed: { type: String, default: '' },
  processed_transactions: [String]
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

// ==========================================
// 3. مسار تسجيل الدخول (Google Auth) - تم حمايته من الأعطال
// ==========================================
app.post('/api/auth/google', async (req, res) => {
  try {
    const { credential } = req.body;
    if (!credential) return res.status(400).json({ error: 'بيانات جوجل مفقودة' });

    // التحقق من التوكن
    const ticket = await googleClient.verifyIdToken({
      idToken: credential,
      audience: GOOGLE_CLIENT_ID
    });
    
    const payload = ticket.getPayload();
    const email = payload.email.toLowerCase().trim();
    const name = payload.name || 'User';

    // محاولة الاتصال بالداتابيز
    await connectDB();

    let isSubActive = false;
    let expiresAt = null;
    let startedAt = null;
    let plan = 'free';

    // إذا كانت قاعدة البيانات متصلة، سجل المستخدم
    if (isConnected) {
        let user = await User.findOne({ email });
        if (!user) {
            user = await User.create({ email, name, subscription_active: false, plan: 'free' });
        } else if (name && user.name !== name) {
            user.name = name;
            await user.save();
        }

        const now = Date.now();
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
    } else {
        // لو لم تتصل الداتابيز، ارسل رسالة للواجهة ليعرف معاذ السبب
        return res.status(500).json({ error: 'قاعدة البيانات MongoDB غير متصلة، يرجى فحص رابط MONGODB_URI في Vercel.' });
    }

    const token = jwt.sign({ email, name }, JWT_SECRET, { expiresIn: '30d' });

    res.cookie('token', token, { httpOnly: true, secure: true, sameSite: 'none', maxAge: 30 * 24 * 60 * 60 * 1000 });
    res.cookie('session_token', token, { httpOnly: true, secure: true, sameSite: 'none', maxAge: 30 * 24 * 60 * 60 * 1000 });

    return res.json({
      success: true,
      user: { email, name, subscriptionActive: isSubActive, startedAt, expiresAt, plan }
    });

  } catch (err) {
    console.error('Auth Error:', err);
    // سيطبع الخطأ في الواجهة لتعرف المشكلة
    return res.status(500).json({ error: 'حدث خطأ أثناء المصادقة مع جوجل: ' + err.message });
  }
});

const requireAuth = (req, res, next) => {
  const token = req.cookies?.session_token || req.cookies?.token;
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
    const token = req.cookies?.session_token || req.cookies?.token;
    if (!token) return res.status(401).json({ error: 'Not authenticated' });

    const decoded = jwt.verify(token, JWT_SECRET);
    await connectDB();

    if (isConnected) {
        const user = await User.findOne({ email: decoded.email.toLowerCase().trim() });
        if (!user) {
            res.clearCookie('token'); res.clearCookie('session_token');
            return res.status(401).json({ error: 'User not found' });
        }
        const now = Date.now();
        let isSubActive = false;
        if (user.subscription_active && user.expires_at > now) {
            isSubActive = true;
        } else if (user.subscription_active && user.expires_at <= now) {
            user.subscription_active = false; user.plan = 'free'; await user.save();
        }
        return res.json({
            email: user.email, name: user.name, subscriptionActive: isSubActive,
            startedAt: isSubActive ? user.started_at : null, expiresAt: isSubActive ? user.expires_at : null, plan: user.plan
        });
    } else {
        // إذا كان السيرفر مفصول، يعتمد على التوكن مؤقتاً لكي لا ينهار
        return res.json({ email: decoded.email, name: decoded.name, subscriptionActive: false, plan: 'free' });
    }
  } catch (err) {
    res.clearCookie('token'); res.clearCookie('session_token');
    return res.status(401).json({ error: 'Invalid session' });
  }
});

app.post('/api/logout', (req, res) => {
  res.clearCookie('token', { sameSite: 'none', secure: true });
  res.clearCookie('session_token', { sameSite: 'none', secure: true });
  res.json({ success: true });
});

// ==========================================
// 5. الحذف وإحصائيات الكوبونات
// ==========================================
app.post('/api/delete-account', requireAuth, async (req, res) => {
    try {
        await connectDB();
        if (isConnected) await User.findOneAndDelete({ email: req.userEmail });
        res.clearCookie('token', { sameSite: 'none', secure: true });
        res.clearCookie('session_token', { sameSite: 'none', secure: true });
        res.json({ success: true, message: 'Account permanently deleted' });
    } catch (err) {
        res.status(500).json({ error: 'Failed to delete account' });
    }
});

app.get('/api/promo-stats', async (req, res) => {
    try {
        await connectDB();
        if (!isConnected) return res.json({ active: true, usedSeats: 0, maxSeats: 15, remaining: 15, currentRank: 1 });

        let promo = await Coupon.findOne({ code: 'MOAZA2FREE' });
        if (!promo) promo = await Coupon.create({ code: 'MOAZA2FREE', type: 'free', maxUses: 15, usedCount: 0, active: true });

        const usedSeats = promo.usedCount;
        const maxSeats = promo.maxUses;
        const remaining = Math.max(0, maxSeats - usedSeats);
        const currentRank = usedSeats + 1;

        res.json({ active: remaining > 0, usedSeats, maxSeats, remaining, currentRank });
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

// ==========================================
// 6. تفعيل الكوبونات 
// ==========================================
app.post('/api/apply-coupon', requireAuth, async (req, res) => {
  const { couponCode } = req.body;
  if (!couponCode) return res.status(400).json({ error: 'No code provided' });

  const code = couponCode.trim().toUpperCase();

  try {
    await connectDB();
    if (!isConnected) return res.status(500).json({ error: 'لا يمكن تفعيل الكوبون، قاعدة البيانات غير متصلة.' });

    let existing = await Coupon.findOne({ code });
    if (!existing && code === 'MOAZA2FREE') {
      existing = await Coupon.create({ code: 'MOAZA2FREE', type: 'free', maxUses: 15, usedCount: 0, active: true });
    }

    const coupon = await Coupon.findOneAndUpdate(
      { code: code, active: true, $expr: { $lt: ["$usedCount", "$maxUses"] } },
      { $inc: { usedCount: 1 } },
      { new: true }
    );

    if (!coupon) return res.status(400).json({ error: 'الكود غير صحيح، أو اكتمل العدد المسموح.' });

    if (coupon.type === 'free') {
      const now = Date.now();
      const oneMonthAhead = now + 30 * 24 * 60 * 60 * 1000;
      await User.findOneAndUpdate(
        { email: req.userEmail },
        { subscription_active: true, plan: 'VIP_PRO', started_at: now, expires_at: oneMonthAhead, couponUsed: code },
        { upsert: true, new: true }
      );
      return res.json({ success: true, type: 'free', message: 'VIP Activated' });
    }

    if (coupon.type === 'percent') return res.json({ type: 'percent', discount: coupon.discount });

  } catch (err) {
    res.status(500).json({ error: 'حدث خطأ في النظام' });
  }
});

// ==========================================
// 7. Paymob 
// ==========================================
const planDurations = { month1: 30*24*60*60*1000, month3: 90*24*60*60*1000, month6: 180*24*60*60*1000, year1: 365*24*60*60*1000 };

app.post('/api/create-payment', requireAuth, async (req, res) => {
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

    await connectDB();
    if (couponCode && isConnected) {
      const coupon = await Coupon.findOne({ code: couponCode.trim().toUpperCase(), type: 'percent', active: true });
      if (coupon) amount = Math.round(amount * (1 - coupon.discount));
    }

    const authRes = await axios.post('https://accept.paymob.com/api/auth/tokens', { api_key: process.env.PAYMOB_API_KEY });
    const paymobToken = authRes.data.token;
    const orderRes = await axios.post('https://accept.paymob.com/api/ecommerce/orders', { auth_token: paymobToken, delivery_needed: 'false', amount_cents: amount, currency: 'EGP', items: [] });
    const paymentKeyRes = await axios.post('https://accept.paymob.com/api/acceptance/payment_keys', {
      auth_token: paymobToken, amount_cents: amount, expiration: 3600, order_id: orderRes.data.id,
      billing_data: { apartment: 'NA', email: req.userEmail, floor: 'NA', first_name: req.userName || 'Sub', street: 'NA', building: 'NA', phone_number: '+201000000000', shipping_method: 'PKG', postal_code: 'NA', city: 'Cairo', country: 'EG', last_name: 'User', state: 'Cairo' },
      currency: 'EGP', integration_id: process.env.PAYMOB_INTEGRATION_ID
    });

    res.json({ url: `https://accept.paymob.com/api/acceptance/iframes/${process.env.PAYMOB_IFRAME_ID}?payment_token=${paymentKeyRes.data.token}` });
  } catch (err) {
    res.status(500).json({ error: 'Failed to initiate payment' });
  }
});

app.post('/api/paymob-webhook', async (req, res) => {
  try {
    const data = req.body.obj;
    const success = data?.success;
    const rawEmail = data?.order?.shipping_data?.email || data?.customer?.email;

    if (success && rawEmail) {
      const email = rawEmail.toLowerCase().trim();
      await connectDB();
      if (isConnected) {
        const user = await User.findOne({ email });
        if (user) {
          const now = Date.now();
          user.subscription_active = true; user.plan = 'PRO_PAID'; user.started_at = now; user.expires_at = now + planDurations.month1;
          await user.save();
        }
      }
    }
    res.sendStatus(200);
  } catch (err) {
    res.sendStatus(500);
  }
});

app.get('/api/launch-app', requireAuth, async (req, res) => {
  try {
    await connectDB();
    if (isConnected) {
        const user = await User.findOne({ email: req.userEmail });
        if (!user || !user.subscription_active || user.expires_at < Date.now()) {
        return res.status(403).send('<h1 style="text-align:center; margin-top:50px; font-family:sans-serif;">عفواً، انتهى اشتراكك أو لم يتم تفعيله. يرجى الترقية لـ PRO.</h1>');
        }
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
