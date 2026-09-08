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

// الاتصال السلس بقاعدة بيانات MongoDB Atlas
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

// تصميم جدول المستخدمين
const userSchema = new mongoose.Schema({
  email: { type: String, unique: true, required: true },
  name: String,
  subscription_active: { type: Boolean, default: false },
  plan: { type: String, default: 'free' },
  expires_at: { type: Number, default: 0 }
}, { timestamps: true });

const User = mongoose.models.User || mongoose.model('User', userSchema);

const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);
const JWT_SECRET = process.env.JWT_SECRET || 'artify_jwt_secret_key_2026';

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
// 1. تسجيل الدخول وحفظ البيانات في MongoDB
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
    const email = payload.email;
    const name = payload.name;

    let isSubActive = false;
    let expiresAt = null;

    await connectDB();

    if (isConnected) {
      try {
        let user = await User.findOne({ email });
        if (!user) {
          user = await User.create({ email, name, subscription_active: false, expires_at: 0 });
          console.log('New User Created in MongoDB:', email);
        }

        if (user && user.subscription_active) {
          isSubActive = true;
          expiresAt = user.expires_at || (Date.now() + 30 * 24 * 60 * 60 * 1000);
        }
      } catch (dbErr) {
        console.warn('MongoDB query warning:', dbErr.message);
      }
    }

    const token = jwt.sign({ email, name, isSubActive }, JWT_SECRET, { expiresIn: '30d' });
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
        expiresAt: isSubActive ? expiresAt : null
      }
    });

  } catch (err) {
    console.error('Google Auth Error:', err);
    return res.status(500).json({ error: 'Authentication failed' });
  }
});

// استرجاع حالة الجلسة عند عمل Refresh
app.get('/api/me', async (req, res) => {
  try {
    const token = req.cookies?.session_token || req.cookies?.token;
    if (!token) return res.status(401).json({ error: 'Not authenticated' });

    const decoded = jwt.verify(token, JWT_SECRET);
    let isSubActive = decoded.isSubActive || false;
    let expiresAt = null;
    let plan = 'Free';

    await connectDB();

    if (isConnected) {
      try {
        const user = await User.findOne({ email: decoded.email });
        if (user && user.subscription_active) {
          isSubActive = true;
          plan = user.plan || 'PRO';
          expiresAt = (user.expires_at && Number(user.expires_at) > Date.now())
            ? user.expires_at
            : Date.now() + 30 * 24 * 60 * 60 * 1000;
        }
      } catch (e) {
        console.warn('MongoDB fetch warning:', e.message);
      }
    }

    return res.json({
      email: decoded.email,
      name: decoded.name,
      subscriptionActive: isSubActive,
      expiresAt: isSubActive ? (expiresAt || Date.now() + 30 * 24 * 60 * 60 * 1000) : null,
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
// 2. تفعيل الكوبونات وتحديث MongoDB
// ==========================================

app.post('/api/apply-coupon', requireAuth, async (req, res) => {
  const { couponCode } = req.body;
  if (!couponCode) return res.status(400).json({ error: 'No code provided' });

  const code = couponCode.trim().toUpperCase();

  if (code === 'VIP2026' || code === 'ARTIFYFREE') {
    const oneMonthAhead = Date.now() + 30 * 24 * 60 * 60 * 1000;

    await connectDB();
    if (isConnected) {
      try {
        await User.findOneAndUpdate(
          { email: req.userEmail },
          { subscription_active: true, plan: 'VIP_PRO', expires_at: oneMonthAhead },
          { upsert: true, new: true }
        );
      } catch (e) {
        console.error('Coupon DB update error:', e.message);
      }
    }

    const updatedToken = jwt.sign(
      { email: req.userEmail, name: req.userName, isSubActive: true },
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
// 3. بوابة الدفع Paymob
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
    const email = data?.order?.shipping_data?.email || data?.customer?.email;

    if (success && email) {
      await connectDB();
      const oneMonthAhead = Date.now() + 30 * 24 * 60 * 60 * 1000;
      await User.findOneAndUpdate(
        { email },
        { subscription_active: true, plan: 'PRO_PAID', expires_at: oneMonthAhead },
        { upsert: true }
      );
    }
    res.sendStatus(200);
  } catch (err) {
    res.sendStatus(500);
  }
});

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
