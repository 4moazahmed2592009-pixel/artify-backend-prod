const express = require('express');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const { OAuth2Client } = require('google-auth-library');
const mongoose = require('mongoose');
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
// 3. مسار تسجيل الدخول (Google Auth)
// ==========================================
app.post('/api/auth/google', async (req, res) => {
  try {
    const { credential } = req.body;
    if (!credential) return res.status(400).json({ error: 'بيانات جوجل مفقودة' });

    const ticket = await googleClient.verifyIdToken({
      idToken: credential,
      audience: GOOGLE_CLIENT_ID
    });
    
    const payload = ticket.getPayload();
    const email = payload.email.toLowerCase().trim();
    const name = payload.name || 'User';

    await connectDB();

    let isSubActive = false;
    let expiresAt = null;
    let startedAt = null;
    let plan = 'free';

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
// 4. الحذف وإحصائيات الكوبونات
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
// 5. Whop Webhook (استقبال إشعار الدفع وتفعيل الاشتراك)
// ==========================================
app.post('/api/whop-webhook', async (req, res) => {
  try {
    const eventData = req.body;
    console.log('Received Whop Webhook Action:', eventData?.action || 'Event received');

    // استخراج الإيميل سواء كان الحدث payment أو membership
    let email = '';
    if (eventData?.data?.user?.email) {
        email = eventData.data.user.email;
    } else if (eventData?.data?.email) {
        email = eventData.data.email;
    } else if (eventData?.user?.email) {
        email = eventData.user.email;
    }

    if (email) {
      email = email.toLowerCase().trim();
      await connectDB();
      if (isConnected) {
        const user = await User.findOne({ email });
        const now = Date.now();
        const duration = 30 * 24 * 60 * 60 * 1000; // مدة افتراضية شهر قابلة للتجديد

        if (user) {
          user.subscription_active = true; 
          user.plan = 'PRO_WHOP'; 
          user.started_at = now; 
          user.expires_at = now + duration; 
          await user.save();
          console.log(`✅ User ${email} successfully activated via Whop.`);
        } else {
          // إذا دفع عميل جديد قبل تسجيل الدخول لأول مرة، يُنشأ له الحساب مفعلاً
          await User.create({
            email,
            name: email.split('@')[0],
            subscription_active: true,
            plan: 'PRO_WHOP',
            started_at: now,
            expires_at: now + duration
          });
          console.log(`✅ New user ${email} created & activated via Whop.`);
        }
      }
    }
    
    // تأكيد استلام الطلب لمنصة Whop
    return res.status(200).json({ received: true });
  } catch (err) {
    console.error('❌ Whop Webhook Error:', err);
    return res.status(500).send('Webhook Processing Error');
  }
});

// ==========================================
// 6. تشغيل الأداة
// ==========================================
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
