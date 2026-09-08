const express = require('express');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const { OAuth2Client } = require('google-auth-library');
const { createClient } = require('@supabase/supabase-js');
const axios = require('axios');
const path = require('path');

const app = express();

// إعدادات Middleware الأساسية
app.use(express.json());
app.use(cookieParser());
app.use(cors({
  origin: true,
  credentials: true
}));

// تقديم ملفات واجهة المستخدم الثابتة (HTML / CSS / الصور)
app.use(express.static(path.join(__dirname, 'public')));

// الاتصال بقاعدة بيانات Supabase
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_KEY;
const supabase = createClient(supabaseUrl, supabaseKey);

// عميل المصادقة مع Google
const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

// Middleware للتحقق من هوية المشترك
const requireAuth = (req, res, next) => {
  const token = req.cookies?.session_token || req.cookies?.token;
  if (!token) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'artify_secret_key_123');
    req.userEmail = decoded.email;
    req.userName = decoded.name;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired session' });
  }
};

// ==========================================
// 1. مسارات المصادقة والمستخدمين (Auth & User)
// ==========================================

// تسجيل الدخول بواسطة Google
app.post('/api/auth/google', async (req, res) => {
  try {
    const { credential } = req.body;
    if (!credential) return res.status(400).json({ error: 'Missing credential' });

    const ticket = await googleClient.verifyIdToken({
      idToken: credential,
      audience: process.env.GOOGLE_CLIENT_ID
    });
    const payload = ticket.getPayload();
    const { email, name } = payload;

    // فحص هل المستخدم مسجل مسبقاً في Supabase
    let { data: user } = await supabase
      .from('users')
      .select('*')
      .eq('email', email)
      .single();

    if (!user) {
      const { data: newUser, error: insertError } = await supabase
        .from('users')
        .insert({
          email,
          name,
          subscription_active: false,
          expires_at: 0
        })
        .select()
        .single();

      if (insertError) {
        console.error('Supabase insert error:', insertError);
        return res.status(500).json({ error: 'Failed to create user record' });
      }
      user = newUser;
    }

    // توليد التوكن وتخزينه في الكوكيز
    const token = jwt.sign(
      { email: user.email, name: user.name },
      process.env.JWT_SECRET || 'artify_secret_key_123',
      { expiresIn: '30d' }
    );

    res.cookie('session_token', token, {
      httpOnly: true,
      secure: true,
      sameSite: 'none',
      maxAge: 30 * 24 * 60 * 60 * 1000 // 30 يوماً
    });

    res.json({ success: true, user: { email: user.email, name: user.name } });
  } catch (err) {
    console.error('Google Auth Error:', err);
    res.status(500).json({ error: 'Authentication failed' });
  }
});

// جلب بيانات الحساب الحالي (المسار الذي كان يرجع 404)
app.get('/api/me', async (req, res) => {
  try {
    const token = req.cookies?.session_token || req.cookies?.token;
    if (!token) {
      return res.status(401).json({ error: 'Not authenticated' });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'artify_secret_key_123');

    const { data: user, error } = await supabase
      .from('users')
      .select('*')
      .eq('email', decoded.email)
      .single();

    if (error || !user) {
      return res.status(401).json({ error: 'User not found in database' });
    }

    const isSubActive = Boolean(user.subscription_active && Number(user.expires_at || 0) > Date.now());

    res.json({
      email: user.email,
      name: user.name || decoded.name,
      subscriptionActive: isSubActive,
      expiresAt: user.expires_at,
      plan: user.plan
    });
  } catch (err) {
    res.status(401).json({ error: 'Invalid session' });
  }
});

// تسجيل الخروج
app.post('/api/logout', (req, res) => {
  res.clearCookie('session_token', { sameSite: 'none', secure: true });
  res.clearCookie('token', { sameSite: 'none', secure: true });
  res.json({ success: true });
});

// ==========================================
// 2. الكوبونات وبوابات الدفع (Paymob & Coupons)
// ==========================================

// تطبيق أكواد الخصم والاشتراكات المجانية
app.post('/api/apply-coupon', requireAuth, async (req, res) => {
  const { couponCode } = req.body;
  if (!couponCode) return res.status(400).json({ error: 'No code provided' });

  const code = couponCode.trim().toUpperCase();

  // كوبون VIP لتفعيل حساب تجريبي مجاناً
  if (code === 'VIP2026' || code === 'ARTIFYFREE') {
    const oneMonthFromNow = Date.now() + 30 * 24 * 60 * 60 * 1000;

    await supabase
      .from('users')
      .update({
        subscription_active: true,
        plan: 'VIP_MONTH',
        expires_at: oneMonthFromNow
      })
      .eq('email', req.userEmail);

    return res.json({ type: 'free', message: 'VIP Activated' });
  }

  // كوبونات الخصم بالنسبة المئوية
  if (code === 'DISCOUNT20') {
    return res.json({ type: 'percent', discount: 0.20 });
  }
  if (code === 'SAVE50') {
    return res.json({ type: 'percent', discount: 0.50 });
  }

  res.status(400).json({ error: 'كود خصم غير صالح' });
});

// إنشاء رابط الدفع مع Paymob
app.post('/api/create-payment', requireAuth, async (req, res) => {
  try {
    const { plan, couponCode } = req.body;
    
    // أسعار الباقات بالجنيه المصري (بالقروش)
    const basePrices = {
      month1: Number(process.env.PAYMOB_PRICE_MONTH_EGP || 500) * 100,
      month3: Number(process.env.PAYMOB_PRICE_3MONTH_EGP || 1250) * 100,
      month6: Number(process.env.PAYMOB_PRICE_6MONTH_EGP || 2000) * 100,
      year1: Number(process.env.PAYMOB_PRICE_YEAR_EGP || 3500) * 100,
    };

    let amount = basePrices[plan] || basePrices.month1;

    // حساب الخصم إن وجد
    if (couponCode && couponCode.toUpperCase() === 'DISCOUNT20') amount = Math.round(amount * 0.8);
    if (couponCode && couponCode.toUpperCase() === 'SAVE50') amount = Math.round(amount * 0.5);

    // 1. تسجيل الدخول إلى Paymob
    const authRes = await axios.post('https://accept.paymob.com/api/auth/tokens', {
      api_key: process.env.PAYMOB_API_KEY
    });
    const paymobToken = authRes.data.token;

    // 2. إنشاء الطلب
    const orderRes = await axios.post('https://accept.paymob.com/api/ecommerce/orders', {
      auth_token: paymobToken,
      delivery_needed: 'false',
      amount_cents: amount,
      currency: 'EGP',
      items: []
    });
    const orderId = orderRes.data.id;

    // 3. إنشاء مفتاح الدفع (Payment Key)
    const paymentKeyRes = await axios.post('https://accept.paymob.com/api/acceptance/payment_keys', {
      auth_token: paymobToken,
      amount_cents: amount,
      expiration: 3600,
      order_id: orderId,
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

    const paymentToken = paymentKeyRes.data.token;
    const iframeId = process.env.PAYMOB_IFRAME_ID;

    // إرجاع رابط نافذة الدفع
    res.json({
      url: `https://accept.paymob.com/api/acceptance/iframes/${iframeId}?payment_token=${paymentToken}`
    });
  } catch (err) {
    console.error('Paymob Error:', err.response?.data || err.message);
    res.status(500).json({ error: 'Failed to initiate payment' });
  }
});

// استقبال تأكيد الدفع من Paymob (Webhook)
app.post('/api/paymob-webhook', async (req, res) => {
  try {
    const data = req.body.obj;
    const success = data?.success;
    const email = data?.order?.shipping_data?.email || data?.customer?.email;

    if (success && email) {
      // مدة الاشتراك: شهر افتراضياً (30 يوماً)
      const expiry = Date.now() + 30 * 24 * 60 * 60 * 1000;

      await supabase
        .from('users')
        .update({
          subscription_active: true,
          plan: 'PRO_PAID',
          expires_at: expiry
        })
        .eq('email', email);
    }
    res.sendStatus(200);
  } catch (err) {
    console.error('Webhook Error:', err);
    res.sendStatus(500);
  }
});

// ==========================================
// 3. التقييمات وتشغيل الأداة (Reviews & Tool)
// ==========================================

// جلب إحصائيات المشتركين وآخر التقييمات
app.get('/api/stats', async (req, res) => {
  try {
    const { count: subscribersCount } = await supabase
      .from('users')
      .select('*', { count: 'exact', head: true })
      .eq('subscription_active', true);

    const { data: reviews } = await supabase
      .from('reviews')
      .select('user_name, rating, comment, created_at')
      .order('created_at', { ascending: false })
      .limit(6);

    res.json({
      subscribersCount: subscribersCount || 0,
      reviews: reviews || []
    });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch statistics' });
  }
});

// إضافة تقييم جديد للمشتركين فقط
app.post('/api/reviews', requireAuth, async (req, res) => {
  const { rating, comment } = req.body;
  if (!rating || !comment) return res.status(400).json({ error: 'Missing data' });

  const { data: user } = await supabase
    .from('users')
    .select('*')
    .eq('email', req.userEmail)
    .single();

  const active = user && Boolean(user.subscription_active && Number(user.expires_at || 0) > Date.now());
  if (!active) return res.status(403).json({ error: 'Only active subscribers can leave a review' });

  const { error } = await supabase.from('reviews').insert({
    user_email: user.email,
    user_name: user.name || req.userName || 'Subscriber',
    rating: Number(rating),
    comment: comment.trim()
  });

  if (error) return res.status(500).json({ error: 'Failed to save review' });
  res.json({ success: true });
});

// تشغيل وتوجيه المشترك إلى أداة التوليد (Canvas Workspace)
app.get('/api/launch-app', requireAuth, async (req, res) => {
  const { data: user } = await supabase
    .from('users')
    .select('*')
    .eq('email', req.userEmail)
    .single();

  const active = user && Boolean(user.subscription_active && Number(user.expires_at || 0) > Date.now());
  if (!active) {
    return res.status(403).send('Unauthorized: Subscription required');
  }

  const toolUrl = process.env.TOOL_URL || 'https://example.com';
  res.redirect(toolUrl);
});

// مسار توجيه افتراضي للواجهة
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// تشغيل السيرفر
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Artify Server is running on port ${PORT}`);
});

module.exports = app;
