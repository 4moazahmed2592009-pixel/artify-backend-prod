const express = require('express');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const { OAuth2Client } = require('google-auth-library');
const { createClient } = require('@supabase/supabase-js');
const axios = require('axios');
const path = require('path');

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(cors({
  origin: true,
  credentials: true
}));

// تقديم الملفات الثابتة (واجهة الموقع)
app.use(express.static(path.join(__dirname, 'public')));

// إعداد Supabase الآمن (Fail-Safe)
let supabase = null;
try {
  if (process.env.SUPABASE_URL && process.env.SUPABASE_KEY) {
    supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_KEY);
  }
} catch (e) {
  console.warn('Supabase initialization warning:', e.message);
}

const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);
const JWT_SECRET = process.env.JWT_SECRET || 'artify_jwt_secret_key_2026';

// Middleware لفحص تسجيل الدخول
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
// 1. تسجيل الدخول وحفظ الجلسة الثابتة
// ==========================================

app.post('/api/auth/google', async (req, res) => {
  try {
    const { credential } = req.body;
    if (!credential) return res.status(400).json({ error: 'Missing credential' });

    // التحقق من حساب جوجل
    const ticket = await googleClient.verifyIdToken({
      idToken: credential,
      audience: process.env.GOOGLE_CLIENT_ID
    });
    const payload = ticket.getPayload();
    const email = payload.email;
    const name = payload.name;

    let isSubActive = false;
    let expiresAt = 0;

    // المزامنة مع Supabase في الخلفية
    if (supabase) {
      try {
        let { data: user } = await supabase
          .from('users')
          .select('*')
          .eq('email', email)
          .maybeSingle();

        if (!user) {
          const { data: newUser } = await supabase
            .from('users')
            .insert({
              email,
              name,
              subscription_active: false,
              expires_at: 0
            })
            .select()
            .maybeSingle();
          if (newUser) user = newUser;
        }

        if (user && user.subscription_active) {
          isSubActive = true;
          expiresAt = user.expires_at || (Date.now() + 30 * 24 * 60 * 60 * 1000);
        }
      } catch (dbErr) {
        console.warn('Supabase sync skipped:', dbErr.message);
      }
    }

    // إنشاء توكن الجلسة وتخزينه في الكوكيز
    const token = jwt.sign(
      { email, name, isSubActive },
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
        expiresAt: isSubActive ? expiresAt : null
      }
    });

  } catch (err) {
    console.error('Auth Error:', err);
    return res.status(500).json({ error: 'Authentication failed' });
  }
});

// جلب بيانات الحساب مع حفظ حالة الاشتراك عند كل Refresh
app.get('/api/me', async (req, res) => {
  try {
    const token = req.cookies?.session_token || req.cookies?.token;
    if (!token) return res.status(401).json({ error: 'Not authenticated' });

    const decoded = jwt.verify(token, JWT_SECRET);
    let isSubActive = decoded.isSubActive || false;
    let expiresAt = null;
    let plan = 'Free';

    if (supabase) {
      try {
        const { data: user } = await supabase
          .from('users')
          .select('*')
          .eq('email', decoded.email)
          .maybeSingle();

        if (user && user.subscription_active) {
          isSubActive = true;
          plan = user.plan || 'PRO';
          // ضمان ظهور تاريخ مستقبلي حقيقي بدلاً من 1970
          expiresAt = Number(user.expires_at) > Date.now()
            ? user.expires_at 
            : Date.now() + 30 * 24 * 60 * 60 * 1000;
        }
      } catch (e) {
        console.warn('Supabase fetch error:', e.message);
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

// تسجيل الخروج
app.post('/api/logout', (req, res) => {
  res.clearCookie('session_token', { sameSite: 'none', secure: true });
  res.clearCookie('token', { sameSite: 'none', secure: true });
  res.json({ success: true });
});

// ==========================================
// 2. الكوبونات وتفعيل الاشتراك الفوري
// ==========================================

app.post('/api/apply-coupon', requireAuth, async (req, res) => {
  const { couponCode } = req.body;
  if (!couponCode) return res.status(400).json({ error: 'No code provided' });

  const code = couponCode.trim().toUpperCase();

  // تفعيل حساب PRO مجاني ومستقر لمدة شهر
  if (code === 'VIP2026' || code === 'ARTIFYFREE') {
    const oneMonthAhead = Date.now() + 30 * 24 * 60 * 60 * 1000;

    if (supabase) {
      try {
        await supabase
          .from('users')
          .update({
            subscription_active: true,
            plan: 'VIP_PRO',
            expires_at: oneMonthAhead
          })
          .eq('email', req.userEmail);
      } catch (e) {
        console.warn('Supabase coupon update error:', e.message);
      }
    }

    // تحديث الكوكيز بحالة الـ PRO لتظل نشطة دائماً حتى لو تعطلت قاعدة البيانات
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

  res.status(400).json({ error: 'كود خصم غير صالح' });
});

// ==========================================
// 3. بوابة الدفع (Paymob)
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

// Webhook لاستقبال تأكيد الدفع
app.post('/api/paymob-webhook', async (req, res) => {
  try {
    const data = req.body.obj;
    const success = data?.success;
    const email = data?.order?.shipping_data?.email || data?.customer?.email;

    if (success && email && supabase) {
      const oneMonthAhead = Date.now() + 30 * 24 * 60 * 60 * 1000;
      await supabase
        .from('users')
        .update({
          subscription_active: true,
          plan: 'PRO_PAID',
          expires_at: oneMonthAhead
        })
        .eq('email', email);
    }
    res.sendStatus(200);
  } catch (err) {
    res.sendStatus(500);
  }
});

// ==========================================
// 4. تشغيل الأداة والتوجيه
// ==========================================

app.get('/api/launch-app', requireAuth, (req, res) => {
  if (!req.isSubActive) {
    return res.status(403).send('Unauthorized: Subscription required');
  }
  res.redirect(process.env.TOOL_URL || 'https://example.com');
});

// إعادة توجيه أي صفحة أخرى إلى index.html
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Artify Server is running on port ${PORT}`);
});

module.exports = app;
