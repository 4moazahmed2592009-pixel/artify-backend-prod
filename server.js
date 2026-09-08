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
const SUPABASE_KEY = process.env.SUPABASE_KEY; 
const supabase = createClient(SUPABASE_URL, SUPABASE_KEY);

// -----------------------------------------------------------------------
// إعدادات Paymob الحديثة
// -----------------------------------------------------------------------
const PAYMOB_API_KEY = process.env.PAYMOB_API_KEY; 
const PAYMOB_PUBLIC_KEY = process.env.PAYMOB_PUBLIC_KEY; 
const PAYMOB_HMAC_SECRET = process.env.PAYMOB_HMAC_SECRET;
const PAYMOB_INTEGRATION_ID = process.env.PAYMOB_INTEGRATION_ID;

// الأسعار الحقيقية الموحدة بالجنيه المصري (بما يعادل أسعار الدولار المطلوبة)
const PLAN_PRICE_EGP = {
  month1: 500,   // يعادل 10 دولار
  month3: 1250,  // يعادل 25 دولار
  month6: 2000,  // يعادل 40 دولار
  year1: 3500,   // يعادل 69 دولار
};

const PLAN_DURATION_DAYS = {
  month1: 30,
  month3: 90,
  month6: 180,
  year1: 365,
};

// -----------------------------------------------------------------------
// التحقق من توقيع Paymob Webhook
// -----------------------------------------------------------------------
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
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.userEmail = payload.email;
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Session expired' });
  }
}

// -----------------------------------------------------------------------
// مسارات المصادقة والمستخدمين 
// -----------------------------------------------------------------------
app.post('/api/auth/google', async (req, res) => {
  const { credential } = req.body;
  if (!credential) return res.status(400).json({ error: 'Missing credential' });

  try {
    const ticket = await googleClient.verifyIdToken({
      idToken: credential,
      audience: GOOGLE_CLIENT_ID,
    });
    const payload = ticket.getPayload();
    const email = payload.email;
    const name = payload.name;

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
    res.status(401).json({ error: 'Google auth failed' });
  }
});

app.post('/api/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ ok: true });
});

app.get('/api/me', requireAuth, async (req, res) => {
  const { data: user, error } = await supabase.from('users').select('*').eq('email', req.userEmail).single();
  if (error || !user) return res.status(404).json({ error: 'User not found' });

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
// إنشاء جلسة دفع Paymob بالسعر الموحد الجديد
// -----------------------------------------------------------------------
app.post('/api/create-payment', requireAuth, async (req, res) => {
  const { plan } = req.body;
  let priceEGP = PLAN_PRICE_EGP[plan];
  if (!priceEGP) return res.status(400).json({ error: 'Invalid plan' });

  const amountCents = priceEGP * 100;
  const merchantOrderId = `artify_${req.userEmail}_${plan}_${Date.now()}`;

  try {
    const { data: user } = await supabase.from('users').select('name').eq('email', req.userEmail).single();
    const [firstName, ...rest] = (user?.name || 'Artify User').split(' ');
    const lastName = rest.join(' ') || 'User';

    const paymobRes = await fetch('https://accept.paymob.com/v1/intention/', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Token ${process.env.PAYMOB_API_KEY}`
      },
      body: JSON.stringify({
        amount: amountCents,
        currency: 'EGP',
        payment_methods: [Number(process.env.PAYMOB_INTEGRATION_ID)],
        items: [],
        billing_data: {
          first_name: firstName,
          last_name: lastName,
          email: req.userEmail,
          phone_number: '+201000000000',
          apartment: 'NA', floor: 'NA', street: 'NA', building: 'NA', city: 'NA', country: 'NA', state: 'NA'
        },
        special_reference: merchantOrderId,
        extras: { merchant_order_id: merchantOrderId }
      })
    });

    if (!paymobRes.ok) throw new Error(`Paymob Intention API failed: ${paymobRes.status}`);
    const data = await paymobRes.json();
    
    const redirectionUrl = `${CLIENT_URL}/?payment_verify=1&plan=${plan}`;
    const iframeUrl = `https://accept.paymob.com/unifiedcheckout/?publicKey=${process.env.PAYMOB_PUBLIC_KEY}&clientSecret=${data.client_secret}&redirection_url=${encodeURIComponent(redirectionUrl)}`;
    
    res.json({ url: iframeUrl });
  } catch (err) {
    console.error('Paymob error:', err.message);
    res.status(500).json({ error: 'Payment creation failed' });
  }
});

// -----------------------------------------------------------------------
// Webhook من Paymob مع التفعيل
// -----------------------------------------------------------------------
app.post('/api/webhook', async (req, res) => {
  const receivedHmac = req.query.hmac || (req.body && req.body.hmac);
  const obj = (req.body && req.body.obj) || req.body;

  if (!obj) return res.status(400).json({ error: 'Missing data' });

  if (receivedHmac && !verifyPaymobHmac(obj, receivedHmac)) {
    console.warn('HMAC verification mismatch');
  }

  const merchantOrderId = 
    obj.special_reference ||
    (obj.order && obj.order.merchant_order_id) ||
    (obj.payment_key_claims && obj.payment_key_claims.billing_data && obj.payment_key_claims.billing_data.extra && obj.payment_key_claims.billing_data.extra.merchant_order_id) ||
    (obj.intention && obj.intention.special_reference);

  console.log('Webhook Received - Order ID:', merchantOrderId, 'Success:', obj.success);

  const success = obj.success === true || obj.success === 'true';

  if (success && merchantOrderId && merchantOrderId.startsWith('artify_')) {
    const parts = merchantOrderId.split('_');
    const email = parts[1];
    const plan = parts[2];
    const durationDays = PLAN_DURATION_DAYS[plan] || 30;
    const expiresAt = Date.now() + durationDays * 24 * 60 * 60 * 1000;

    const { error: updateError } = await supabase.from('users').update({
      subscription_active: true,
      plan,
      expires_at: expiresAt,
    }).eq('email', email);

    if (updateError) console.error('Supabase update error:', updateError.message);
  }

  res.json({ received: true });
});

app.get('/api/tool-access', requireAuth, async (req, res) => {
  const { data: user } = await supabase.from('users').select('*').eq('email', req.userEmail).single();
  const active = user && !!user.subscription_active && Number(user.expires_at || 0) > Date.now();

  if (!active) return res.status(403).json({ error: 'No active subscription' });
  res.json({ url: TOOL_URL });
});

app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
