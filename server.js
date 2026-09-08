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

// تقديم ملفات الواجهة الأمامية
app.use(express.static(path.join(__dirname, 'public')));

// الاتصال بـ Supabase
let supabase = null;
try {
  if (process.env.SUPABASE_URL && process.env.SUPABASE_KEY) {
    supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_KEY);
  }
} catch (e) {
  console.warn('Supabase init warning:', e.message);
}

const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);
const JWT_SECRET = process.env.JWT_SECRET || 'artify_jwt_secret_key_2026';

// Middleware للتحقق من تسجيل الدخول
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
// 1. تسجيل الدخول والربط الحقيقي بـ Supabase
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
    let expiresAt = null;

    if (supabase) {
      try {
        // فحص هل المستخدم مسجل مسبقاً
        let { data: user, error: selectErr } = await supabase
          .from('users')
          .select('*')
          .eq('email', email)
          .maybeSingle();

        if (selectErr) console.error('Supabase Select Error:', selectErr);

        if (!user) {
          // تسجيل المستخدم الجديد داخل الجدول فوراً
          const { data: newUser, error: insertErr } = await supabase
            .from('users')
            .insert([{
              email: email,
              name: name || 'User',
              subscription_active: false,
              expires_at: 0
            }])
            .select()
            .maybeSingle();

          if (insertErr) {
            console.error('Supabase Insert Error:', insertErr);
          } else {
            user = newUser;
            console.log('User created in Supabase:', email);
          }
        }

        if (user && user.subscription_active) {
          isSubActive = true;
          expiresAt = user.expires_at || (Date.now() + 30 * 24 * 60 * 60 * 1000);
        }
      } catch (dbErr) {
        console.error('Supabase Sync Error:', dbErr);
      }
    }

    // إنشاء توكن الجلسة
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

// مسار جلب بيانات المستخدم مع ضمان ثبات الاشتراك
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
          expiresAt = (user.expires_at && Number(user.expires_at) > Date.now())
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
// 2. تفعيل الكوبونات وتحديث Supabase
// ==========================================

app.post('/api/apply-coupon', requireAuth, async (req, res) => {
  const { couponCode } = req.body;
  if (!couponCode) return res.status(400).json({ error: 'No code provided' });

  const code = couponCode.trim().toUpperCase();

  if (code === 'VIP2026' || code === 'ARTIFYFREE') {
    const oneMonthAhead = Date.now() + 30 * 24 * 60 * 60 * 1000;

    if (supabase) {
      try {
        const { error: updateErr } = await supabase
          .from('users')
          .update({
            subscription_active: true,
            plan: 'VIP_PRO',
            expires_at: oneMonthAhead
          })
          .eq('email', req.userEmail);

        if (updateErr) {
          console.warn('First update failed, retrying without expires_at:', updateErr.message);
          await supabase
            .from('users')
            .update({
              subscription_active: true,
              plan: 'VIP_PRO'
            })
            .eq('email', req.userEmail);
        }
      } catch (e) {
        console.error('Coupon DB Error:', e.message);
      }
    }

    // تحديث التوكن في الكوكيز
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

// استقبال تأكيد الدفع التلقائي
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
// 4. التقييمات وتشغيل الأداة
// ==========================================

app.get('/api/stats', async (req, res) => {
  try {
    let subscribersCount = 0;
    let reviews = [];

    if (supabase) {
      const { count } = await supabase
        .from('users')
        .select('*', { count: 'exact', head: true })
        .eq('subscription_active', true);
      subscribersCount = count || 0;

      const { data: revList } = await supabase
        .from('reviews')
        .select('user_name, rating, comment, created_at')
        .order('created_at', { ascending: false })
        .limit(6);
      reviews = revList || [];
    }

    res.json({ subscribersCount, reviews });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch statistics' });
  }
});

app.post('/api/reviews', requireAuth, async (req, res) => {
  const { rating, comment } = req.body;
  if (!rating || !comment) return res.status(400).json({ error: 'Missing data' });
  if (!req.isSubActive) return res.status(403).json({ error: 'Only active subscribers can review' });

  if (supabase) {
    const { error } = await supabase.from('reviews').insert({
      user_email: req.userEmail,
      user_name: req.userName || 'Subscriber',
      rating: Number(rating),
      comment: comment.trim()
    });
    if (error) return res.status(500).json({ error: 'Failed to save review' });
  }

  res.json({ success: true });
});

// فتح الأداة
app.get('/api/launch-app', requireAuth, (req, res) => {
  if (!req.isSubActive) {
    return res.status(403).send('Unauthorized: Subscription required');
  }
  res.redirect(process.env.TOOL_URL || 'https://example.com');
});

// المسار الافتراضي للواجهة
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Artify Server is running on port ${PORT}`);
});

module.exports = app;
