require('dotenv').config();
const crypto = require('crypto');
const express = require('express');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const path = require('path');
const { OAuth2Client } = require('google-auth-library');
const { createClient } = require('@supabase/supabase-js');

const app = express();
const PORT = process.env.PORT || 4000;
const CLIENT_URL = process.env.CLIENT_URL || `http://localhost:${PORT}`;
const JWT_SECRET = process.env.JWT_SECRET || 'change-this-secret';
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const TOOL_URL = process.env.TOOL_URL;

const googleClient = new OAuth2Client(GOOGLE_CLIENT_ID);

// -----------------------------------------------------------------------
// الربط بقاعدة بيانات Supabase
// -----------------------------------------------------------------------
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_KEY; // نستخدم الـ Secret Key هنا لتمكين السيرفر من القراءة والكتابة
const supabase = createClient(SUPABASE_URL, SUPABASE_KEY);

// -----------------------------------------------------------------------
// إعدادات Paymob
// -----------------------------------------------------------------------
const PAYMOB_API_KEY = process.env.PAYMOB_API_KEY;
const PAYMOB_HMAC_SECRET = process.env.PAYMOB_HMAC_SECRET;
const PAYMOB_INTEGRATION_ID = process.env.PAYMOB_INTEGRATION_ID;
const PAYMOB_IFRAME_ID = process.env.PAYMOB_IFRAME_ID;
const PAYMOB_BASE_URL = (process.env.PAYMOB_BASE_URL || 'https://accept.paymob.com/api').replace(/\/$/, '');

const PLAN_PRICE_EGP = {
  month1: Number(process.env.PAYMOB_PRICE_MONTH_EGP || 350),
  month3: Number(process.env.PAYMOB_PRICE_3MONTH_EGP || 900),
  month6: Number(process.env.PAYMOB_PRICE_6MONTH_EGP || 1600),
  year1: Number(process.env.PAYMOB_PRICE_YEAR_EGP || 2500),
};

const PLAN_DURATION_DAYS = {
  month1: 30,
  month3: 90,
  month6: 180,
  year1: 365,
};

// -----------------------------------------------------------------------
// دوال Paymob
// -----------------------------------------------------------------------
async function paymobAuth() {
  const res = await fetch(`${PAYMOB_BASE_URL}/auth/tokens`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ api_key: PAYMOB_API_KEY }),
  });
  if (!res.ok) throw new Error(`Paymob auth failed: ${res.status}`);
  const data = await res.json();
  return data.token;
}

async function paymobCreateOrder(authToken, amountCents, merchantOrderId) {
  const res = await fetch(`${PAYMOB_BASE_URL}/ecommerce/orders`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      auth_token: authToken,
      delivery_needed: false,
      amount_cents: amountCents,
      currency: 'EGP',
      merchant_order_id: merchantOrderId,
      items: [],
    }),
  });
  if (!res.ok) throw new Error(`Paymob order creation failed: ${res.status}`);
  const data = await res.json();
  return data.id;
}

async function paymobPaymentKey(authToken, amountCents, orderId, email, name) {
  const [firstName, ...rest] = (name || 'Artify User').split(' ');
  const lastName = rest.join(' ') || 'User';

  const res = await fetch(`${PAYMOB_BASE_URL}/acceptance/payment_keys`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      auth_token: authToken,
      amount_cents: amountCents,
      expiration: 3600,
      order_id: orderId,
      billing_data: {
        apartment: 'NA', email, floor: 'NA', first_name: firstName, street: 'NA',
        building: 'NA', phone_number: '+201000000000', shipping_method: 'NA',
        postal_code: 'NA', city: 'NA', country: 'NA', last_name: lastName, state: 'NA',
      },
      currency: 'EGP',
      integration_id: Number(PAYMOB_INTEGRATION_ID),
    }),
  });
  if (!res.ok) throw new Error(`Paymob payment key failed: ${res.status}`);
  const data = await res.json();
  return data.token;
}

function verifyPaymobHmac(obj, receivedHmac) {
  const fields = [
    'amount_cents', 'created_at', 'currency', 'error_occured',
    'has_parent_transaction', 'id', 'integration_id', 'is_3d_secure',
    'is_auth', 'is_capture', 'is_refunded', 'is_standalone_payment',
    'is_voided', 'order.id', 'owner', 'pending',
    'source_data.pan', 'source_data.sub_type', 'source_data.type', 'success',
  ];

  const concatenated = fields
    .map((f) => {
      const parts = f.split('.');
      let val = obj;
      for (const p of parts) val = val ? val[p] : undefined;
      return val === undefined || val === null ? '' : String(val);
    })
    .join('');

  const computed = crypto
    .createHmac('sha512', PAYMOB_HMAC_SECRET)
    .update(concatenated)
    .digest('hex');

  return computed === receivedHmac;
}

app.use(cors({ origin: CLIENT_URL, credentials: true }));
app.use(cookieParser());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

function requireAuth(req, res, next) {
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ error: 'غير مسجل الدخول' });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.userEmail = payload.email;
    next();
  } catch (e) {
    return res.status(401).json({ error: 'الجلسة منتهية، سجّل الدخول مجدداً' });
  }
}

// -----------------------------------------------------------------------
// مسارات المصادقة والمستخدمين (باستخدام Supabase)
// -----------------------------------------------------------------------
app.post('/api/auth/google', async (req, res) => {
  const { credential } = req.body;
  if (!credential) return res.status(400).json({ error: 'مفقود الـ credential' });

  try {
    const ticket = await googleClient.verifyIdToken({
      idToken: credential,
      audience: GOOGLE_CLIENT_ID,
    });
    const payload = ticket.getPayload();
    const email = payload.email;
    const name = payload.name;

    // حفظ المستخدم في Supabase (إن لم يكن موجوداً يحدّث الاسم فقط)
    await supabase.from('users').upsert({ email, name }, { onConflict: 'email', ignoreDuplicates: false });

    const token = jwt.sign({ email }, JWT_SECRET, { expiresIn: '30d' });
    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 30 * 24 * 60 * 60 * 1000,
    });

    res.json({ ok: true, email, name });
  } catch (err) {
    console.error('Google verification error:', err.message);
    res.status(401).json({ error: 'فشل التحقق من حساب جوجل' });
  }
});

app.post('/api/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ ok: true });
});

app.get('/api/me', requireAuth, async (req, res) => {
  const { data: user, error } = await supabase.from('users').select('*').eq('email', req.userEmail).single();
  if (error || !user) return res.status(404).json({ error: 'المستخدم غير موجود' });

  const active = !!user.subscription_active && Number(user.expires_at || 0) > Date.now();
  res.json({
    email: user.email,
    name: user.name,
    subscriptionActive: active,
    plan: user.plan || null,
    expiresAt: user.expires_at || null,
  });
});

// -----------------------------------------------------------------------
// إنشاء جلسة دفع Paymob مع تعديل السعر حسب المنطقة
// -----------------------------------------------------------------------
app.post('/api/create-payment', requireAuth, async (req, res) => {
  const { plan, region } = req.body;
  let priceEGP = PLAN_PRICE_EGP[plan];
  if (!priceEGP) return res.status(400).json({ error: 'باقة غير معروفة' });

  if (region === 'ARAB') priceEGP = Math.round(priceEGP * 1.3);
  if (region === 'GLOBAL') priceEGP = Math.round(priceEGP * 2.2);

  const amountCents = Math.round(priceEGP * 100);
  const merchantOrderId = `artify_${req.userEmail}_${plan}_${Date.now()}`;

  try {
    const authToken = await paymobAuth();
    const orderId = await paymobCreateOrder(authToken, amountCents, merchantOrderId);
    
    const { data: user } = await supabase.from('users').select('name').eq('email', req.userEmail).single();
    const paymentToken = await paymobPaymentKey(authToken, amountCents, orderId, req.userEmail, user ? user.name : '');

    const iframeUrl = `${PAYMOB_BASE_URL}/acceptance/iframes/${PAYMOB_IFRAME_ID}?payment_token=${paymentToken}`;
    res.json({ url: iframeUrl });
  } catch (err) {
    console.error('Paymob error:', err.message);
    res.status(500).json({ error: 'فشل في إنشاء معاملة الدفع' });
  }
});

// -----------------------------------------------------------------------
// Webhook من Paymob
// -----------------------------------------------------------------------
app.post('/api/webhook', async (req, res) => {
  const receivedHmac = req.query.hmac || (req.body && req.body.hmac);
  const obj = (req.body && req.body.obj) || req.body;

  if (!obj || !receivedHmac) return res.status(400).json({ error: 'بيانات ناقصة' });

  if (!verifyPaymobHmac(obj, receivedHmac)) {
    return res.status(401).json({ error: 'توقيع HMAC غير صحيح' });
  }

  const merchantOrderId = obj.order && obj.order.merchant_order_id;
  const success = obj.success === true || obj.success === 'true';

  if (success && merchantOrderId) {
    const parts = merchantOrderId.split('_'); // artify, email, plan, timestamp
    const email = parts[1];
    const plan = parts[2];
    const durationDays = PLAN_DURATION_DAYS[plan] || 30;
    const expiresAt = Date.now() + durationDays * 24 * 60 * 60 * 1000;

    await supabase.from('users').update({
      subscription_active: true,
      plan,
      expires_at: expiresAt,
    }).eq('email', email);
  }

  res.json({ received: true });
});

// -----------------------------------------------------------------------
// تفعيل الكوبونات وإدارتها
// -----------------------------------------------------------------------
app.post('/api/redeem-coupon', requireAuth, async (req, res) => {
  const { code } = req.body;
  const { data: coupon, error } = await supabase.from('coupons').select('*').eq('code', code).single();

  if (error || !coupon) return res.status(400).json({ error: 'الكود غير موجود' });
  if (coupon.is_used) return res.status(400).json({ error: 'تم استخدام هذا الكود من قبل' });

  // قفل الكود
  await supabase.from('coupons').update({
    is_used: true,
    used_by: req.userEmail,
    used_at: Date.now(),
  }).eq('code', code);

  // تفعيل اشتراك دائم (100 سنة) للمستخدم
  const expiresAt = Date.now() + 100 * 365 * 24 * 60 * 60 * 1000;
  await supabase.from('users').update({
    subscription_active: true,
    plan: 'lifetime',
    expires_at: expiresAt,
  }).eq('email', req.userEmail);

  res.json({ success: true });
});

app.post('/api/admin/generate-coupon', requireAuth, async (req, res) => {
  const adminEmail = '9moazahmed2592009@gmail.com'; // حسابك الأدمن
  if (req.userEmail !== adminEmail) {
    return res.status(403).json({ error: 'غير مصرح لك (حساب المسؤول فقط)' });
  }

  const { code } = req.body;
  if (!code) return res.status(400).json({ error: 'اكتب الكود أولاً' });

  const { error } = await supabase.from('coupons').insert({
    code,
    is_used: false,
    created_by: req.userEmail,
    created_at: Date.now(),
  });

  if (error) return res.status(400).json({ error: 'الكود مكرر أو حدث خطأ' });
  res.json({ success: true, code });
});

// -----------------------------------------------------------------------
// الوصول للأداة
// -----------------------------------------------------------------------
app.get('/api/tool-access', requireAuth, async (req, res) => {
  const { data: user } = await supabase.from('users').select('*').eq('email', req.userEmail).single();
  const active = user && !!user.subscription_active && Number(user.expires_at || 0) > Date.now();

  if (!active) return res.status(403).json({ error: 'مفيش اشتراك ساري' });
  res.json({ url: TOOL_URL });
});

app.listen(PORT, () => {
  console.log(`🚀 السيرفر يعمل بنجاح على البورت ${PORT}`);
});