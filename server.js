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
// 1. الاتصال بقاعدة بيانات MongoDB Atlas
// ==========================================
let isConnected = false;
const connectDB = async () => {
  if (isConnected || !process.env.MONGODB_URI) return;
  try {
    const db = await mongoose.connect(process.env.MONGODB_URI, {
      bufferCommands: false,
    });
    isConnected = db.connections[0].readyState === 1;
    console.log('MongoDB Atlas Connected Successfully');
  } catch (err) {
    console.warn('MongoDB connection deferred:', err.message);
  }
};
connectDB();

// تصميم جدول المستخدمين وتحديد الحقول (تم إضافة couponUsed و started_at)
const userSchema = new mongoose.Schema({
  email: { type: String, unique: true, required: true },
  name: { type: String, default: '' },
  subscription_active: { type: Boolean, default: false },
  plan: { type: String, default: 'free' },
  started_at: { type: Number, default: 0 },
  expires_at: { type: Number, default: 0 },
  couponUsed: { type: String, default: '' }
}, { timestamps: true });

const User = mongoose.models.User || mongoose.model('User', userSchema);

const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);
const JWT_SECRET = process.env.JWT_SECRET || 'artify_jwt_secret_key_2026';

// دالة فحص تسجيل الدخول
const requireAuth = (req, res, next) => {
  const token = req.cookies?.session_token || req.cookies?.token;
  if (!token) return res.status(401).json({ error: 'Authentication required' });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.userEmail = decoded.email;
    req.userName = decoded.name;
    req.isSubActive = decoded.isSubActive || false;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid session' });
  }
};

// ==========================================
// 2. مسارات المصادقة وتسجيل الدخول (Google OAuth)
// ==========================================

app.post('/api/auth/google', async (req, res) => {
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

    await connectDB();

    let isSubActive = false;
    let expiresAt = null;
    let startedAt = null;
    let plan = 'free';

    if (isConnected) {
      try {
        let user = await User.findOne({ email });

        if (!user) {
          user = await User.create({
            email,
            name,
            subscription_active: false,
            plan: 'free',
            started_at: 0,
            expires_at: 0
          });
          console.log('New user created in MongoDB:', email);
        } else {
          if (name && user.name !== name) {
            user.name = name;
            await user.save();
          }

          const now = Date.now();
          if (user.subscription_active && user.expires_at && Number(user.expires_at) > now) {
            isSubActive = true;
            expiresAt = Number(user.expires_at);
            startedAt = Number(user.started_at);
            plan = user.plan || 'PRO';
          }
        }
      } catch (dbErr) {
        console.warn('MongoDB query warning:', dbErr.message);
      }
    }

    const token = jwt.sign(
      { email, name, isSubActive, expiresAt, startedAt, plan },
      JWT_SECRET,
      { expiresIn: '30d' }
    );

    res.cookie('session_token', token, {
      httpOnly: true,
      secure: true,
      sameSite: 'none',
      maxAge: 30 * 24 * 60 * 60 * 1000
    });

    return res.json({
      success: true,
      user: {
        email,
        name,
        subscriptionActive: isSubActive,
        startedAt: isSubActive ? startedAt : null,
        expiresAt: isSubActive ? expiresAt : null,
        plan
      }
    });

  } catch (err) {
    console.error('Google Auth Error:', err);
    return res.status(500).json({ error: 'Authentication failed' });
  }
});

app.get('/api/me', async (req, res) => {
  try {
    const token = req.cookies?.session_token || req.cookies?.token;
    if (!token) return res.status(401).json({ error: 'Not authenticated' });

    const decoded = jwt.verify(token, JWT_SECRET);
    const email = decoded.email.toLowerCase().trim();

    let isSubActive = false;
    let expiresAt = null;
    let startedAt = null;
    let plan = 'free';

    await connectDB();

    if (isConnected) {
      try {
        const user = await User.findOne({ email });
        if (user) {
          const now = Date.now();
          if (user.subscription_active && user.expires_at && Number(user.expires_at) > now) {
            isSubActive = true;
            expiresAt = Number(user.expires_at);
            startedAt = Number(user.started_at);
            plan = user.plan || 'PRO';
          }
        }
      } catch (e) {
        console.warn('MongoDB fetch warning:', e.message);
      }
    } else {
      isSubActive = decoded.isSubActive || false;
      expiresAt = decoded.expiresAt || null;
      startedAt = decoded.startedAt || null;
      plan = decoded.plan || 'free';
    }

    return res.json({
      email,
      name: decoded.name,
      subscriptionActive: isSubActive,
      startedAt: isSubActive ? startedAt : null,
      expiresAt: isSubActive ? expiresAt : null,
      plan
    });
  } catch (err) {
    return res.status(401).json({ error: 'Invalid session' });
  }
});

app.post('/api/logout', (req, res) => {
  res.clearCookie('session_token', { sameSite: 'none', secure: true });
  res.clearCookie('token', { sameSite: 'none', secure: true });
  res.json({ success: true });
});

// ==========================================
// 3. مسارات النظام والحساب (System & Account)
// ==========================================

// مسار لحذف الحساب
app.post('/api/delete-account', requireAuth, async (req, res) => {
    try {
        const email = req.userEmail;
        await connectDB();
        
        if (isConnected) {
            await User.findOneAndDelete({ email });
        }
        
        res.clearCookie('session_token', { sameSite: 'none', secure: true });
        res.clearCookie('token', { sameSite: 'none', secure: true });
        res.json({ success: true, message: 'Account permanently deleted' });
    } catch (err) {
        res.status(500).json({ error: 'Failed to delete account' });
    }
});

// مسار لجلب إحصائيات المقاعد المجانية
app.get('/api/promo-stats', async (req, res) => {
    try {
        await connectDB();
        if (isConnected) {
            const usedSeats = await User.countDocuments({ couponUsed: 'ARTIFYFREE' });
            res.json({ usedSeats });
        } else {
             res.json({ usedSeats: 0 }); // Default if DB not ready
        }
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

// ==========================================
// 4. تفعيل الكوبونات وتثبيت الاشتراك
// ==========================================

app.post('/api/apply-coupon', requireAuth, async (req, res) => {
  const { couponCode } = req.body;
  if (!couponCode) return res.status(400).json({ error: 'No code provided' });

  const code = couponCode.trim().toUpperCase();

  if (code === 'VIP2026' || code === 'ARTIFYFREE') {
    
    await connectDB();
    if (isConnected && code === 'ARTIFYFREE') {
         // التحقق من المقاعد
         const usedSeats = await User.countDocuments({ couponUsed: 'ARTIFYFREE' });
         if (usedSeats >= 15) return res.status(400).json({ error: 'اكتمل عدد المقاعد المجانية!' });
    }

    const now = Date.now();
    const oneMonthAhead = now + 30 * 24 * 60 * 60 * 1000;
    const email = req.userEmail.toLowerCase().trim();

    if (isConnected) {
      try {
        await User.findOneAndUpdate(
          { email },
          { 
            subscription_active: true, 
            plan: 'VIP_PRO', 
            started_at: now,
            expires_at: oneMonthAhead,
            couponUsed: code 
          },
          { upsert: true, new: true }
        );
        console.log(`VIP coupon applied & stored for: ${email}`);
      } catch (e) {
        console.error('Coupon DB update error:', e.message);
      }
    }

    const updatedToken = jwt.sign(
      { 
        email, 
        name: req.userName, 
        isSubActive: true, 
        startedAt: now,
        expiresAt: oneMonthAhead, 
        plan: 'VIP_PRO' 
      },
      JWT_SECRET,
      { expiresIn: '30d' }
    );

    res.cookie('session_token', updatedToken, {
      httpOnly: true,
      secure: true,
      sameSite: 'none',
      maxAge: 30 * 24 * 60 * 60 * 1000
    });

    return res.json({
      success: true,
      type: 'free',
      message: 'VIP Activated',
      expiresAt: oneMonthAhead
    });
  }

  if (code === 'DISCOUNT20') return res.json({ type: 'percent', discount: 0.20 });
  if (code === 'SAVE50') return res.json({ type: 'percent', discount: 0.50 });

  return res.status(400).json({ error: 'كود خصم غير صالح' });
});

// ==========================================
// 5. بوابة الدفع Paymob
// ==========================================

app.post('/api/create-payment', requireAuth, async (req, res) => {
  try {
    const { plan, couponCode } = req.body;
    const basePrices = {
      month1: Number(process.env.PAYMOB_PRICE_MONTH_EGP || 500) * 100,
      month3: Number(process.env.PAYMOB_PRICE_3MONTH_EGP || 1250) * 100,
      month6: Number(process.env.PAYMOB_PRICE_6MONTH_EGP || 2000) * 100,
      year1: Number(process.env.PAYMOB_PRICE_YEAR_EGP || 3500) * 100,
    };

    let amount = basePrices[plan] || basePrices.month1;
    if (couponCode && couponCode.toUpperCase() === 'DISCOUNT20') amount = Math.round(amount * 0.8);
    if (couponCode && couponCode.toUpperCase() === 'SAVE50') amount = Math.round(amount * 0.5);

    const authRes = await axios.post('https://accept.paymob.com/api/auth/tokens', {
      api_key: process.env.PAYMOB_API_KEY
    });
    const paymobToken = authRes.data.token;

    const orderRes = await axios.post('https://accept.paymob.com/api/ecommerce/orders', {
      auth_token: paymobToken,
      delivery_needed: 'false',
      amount_cents: amount,
      currency: 'EGP',
      items: []
    });

    const paymentKeyRes = await axios.post('https://accept.paymob.com/api/acceptance/payment_keys', {
      auth_token: paymobToken,
      amount_cents: amount,
      expiration: 3600,
      order_id: orderRes.data.id,
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
        state: 'Cairo'
      },
      currency: 'EGP',
      integration_id: process.env.PAYMOB_INTEGRATION_ID
    });

    res.json({
      url: `https://accept.paymob.com/api/acceptance/iframes/${process.env.PAYMOB_IFRAME_ID}?payment_token=${paymentKeyRes.data.token}`
    });
  } catch (err) {
    console.error('Paymob Error:', err.response?.data || err.message);
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
      const now = Date.now();
      const oneMonthAhead = now + 30 * 24 * 60 * 60 * 1000;
      await User.findOneAndUpdate(
        { email },
        { subscription_active: true, plan: 'PRO_PAID', started_at: now, expires_at: oneMonthAhead },
        { upsert: true }
      );
      console.log(`Payment Webhook: Activated subscription for ${email}`);
    }
    res.sendStatus(200);
  } catch (err) {
    console.error('Webhook Error:', err.message);
    res.sendStatus(500);
  }
});

// ==========================================
// 6. حماية فتح التطبيق والواجهة
// ==========================================

app.get('/api/launch-app', requireAuth, (req, res) => {
  if (!req.isSubActive) {
    return res.status(403).send('Unauthorized: Subscription required');
  }
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
