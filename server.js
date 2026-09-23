import express from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import jwt from 'jsonwebtoken';
import { OAuth2Client } from 'google-auth-library';
import { MongoClient } from 'mongodb';
import crypto from 'crypto';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

app.post('/api/verify-tool-token', cors({ origin: true, credentials: false }), express.json(), async (req, res) => {
  try {
    const { token } = req.body;
    if (!token) return res.status(400).json({ valid: false, reason: 'missing_token' });

    let decoded;
    try {
      decoded = jwt.verify(token, JWT_SECRET);
    } catch (e) {
      return res.status(200).json({ valid: false, reason: 'invalid_or_expired' });
    }

    const db = await getDb();
    const user = await db.collection('users').findOne({ email: decoded.email });
    if (!user || !user.subscription_active || user.expires_at <= Date.now()) {
      return res.status(200).json({ valid: false, reason: 'subscription_inactive' });
    }

    return res.status(200).json({ valid: true });
  } catch (err) {
    return res.status(200).json({ valid: false, reason: 'server_error' });
  }
});

// 1. حماية CORS
const allowedOrigins = [
  'https://artify-backend-prod.vercel.app',
  'http://localhost:3000'
];

app.use(cors({
  origin: function (origin, callback) {
    if (!origin || allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      callback(new Error('Blocked by CORS'));
    }
  },
  credentials: true
}));

app.use(cookieParser());

// التقاط الـ raw body بدقة للويب هوك
app.use(express.json({
  verify: (req, res, buf) => {
    req.rawBody = buf;
  }
}));

app.use(express.static(path.join(__dirname, 'public')));

// متغيرات البيئة الأساسية
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const JWT_SECRET = process.env.JWT_SECRET;
const MONGODB_URI = process.env.MONGODB_URI;
const WHOP_WEBHOOK_SECRET = process.env.WHOP_WEBHOOK_SECRET;
const TOOL_URL = process.env.TOOL_URL;

const REQUIRED = { GOOGLE_CLIENT_ID, JWT_SECRET, MONGODB_URI, WHOP_WEBHOOK_SECRET, TOOL_URL };
const missing = Object.entries(REQUIRED).filter(([, v]) => !v).map(([k]) => k);
if (missing.length) {
  console.error(`FATAL ERROR: Missing required environment variables: ${missing.join(', ')}`);
  process.exit(1);
}

const googleClient = new OAuth2Client(GOOGLE_CLIENT_ID);
const isProd = process.env.NODE_ENV === 'production';

const EARLY_BIRD_CODE = 'EARLY_BIRD_INTERNAL';
const EARLY_BIRD_MAX_SEATS = 15;
const EARLY_BIRD_DURATION_DAYS = 30;

// تحسين الاتصال بقاعدة البيانات لبيئة Serverless
let dbClientPromise = null;
async function getDb() {
  if (!dbClientPromise) {
    const client = new MongoClient(MONGODB_URI);
    dbClientPromise = client.connect();
  }
  const client = await dbClientPromise;
  return client.db('artify');
}

// ==========================================
// Middlewares: Authentication & Anti-CSRF
// ==========================================

// 1. حماية CSRF الصارمة
function csrfCheck(req, res, next) {
  const csrfHeader = req.headers['x-artify-csrf'];
  if (!csrfHeader || csrfHeader !== '1') {
    return res.status(403).json({ error: 'CSRF token missing or invalid' });
  }
  next();
}

// 2. التحقق من جلسة المستخدم
function requireAuth(req, res, next) {
  try {
    const token = req.cookies.token;
    if (!token) return res.status(401).json({ error: 'Authentication required' });
    const decoded = jwt.verify(token, JWT_SECRET);
    req.userEmail = decoded.email.toLowerCase();
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid session' });
  }
}

// ==========================================
// مسارات المصادقة
// ==========================================
app.post('/api/auth/google', csrfCheck, async (req, res) => {
  try {
    const { credential } = req.body;
    if (!credential) return res.status(400).json({ error: 'Missing credential' });

    const ticket = await googleClient.verifyIdToken({
      idToken: credential,
      audience: GOOGLE_CLIENT_ID,
    });
    const payload = ticket.getPayload();
    const email = payload.email.toLowerCase();
    const name = payload.name;

    const db = await getDb();
    const users = db.collection('users');

    let user = await users.findOne({ email });
    const now = Date.now();

    if (!user) {
      user = {
        email,
        name,
        created_at: now,
        started_at: 0,
        expires_at: 0,
        subscription_active: false,
        plan: 'free',
        whop_id: null
      };
      await users.insertOne(user);
    }

    const token = jwt.sign({ email, name }, JWT_SECRET, { expiresIn: '7d' });

    res.cookie('token', token, {
      httpOnly: true,
      secure: isProd,
      sameSite: isProd ? 'none' : 'lax',
      maxAge: 7 * 24 * 60 * 60 * 1000
    });

    res.json({ success: true, email, name });
  } catch (err) {
    res.status(500).json({ error: 'Authentication failed' });
  }
});

app.get('/api/me', requireAuth, async (req, res) => {
  try {
    const db = await getDb();
    const user = await db.collection('users').findOne({ email: req.userEmail });

    if (!user) return res.status(404).json({ error: 'User not found' });
    const isSubscribed = user.subscription_active && (user.expires_at > Date.now());

    res.json({
      email: user.email,
      name: user.name,
      subscriptionActive: isSubscribed,
      plan: user.plan || 'free',
      startedAt: user.started_at || 0,
      expiresAt: user.expires_at || 0
    });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch session' });
  }
});

// ==========================================
// Webhook الدفع المؤمن (بدون csrfCheck لأنه قادم من خوادم Whop)
// ==========================================
function verifyWhopSignature(req) {
  const webhookId = req.headers['webhook-id'];
  const webhookTimestamp = req.headers['webhook-timestamp'];
  const signatureHeader = req.headers['webhook-signature'];

  if (!webhookId || !webhookTimestamp || !signatureHeader) return { valid: false };

  const tsSeconds = parseInt(webhookTimestamp, 10);
  const nowSeconds = Math.floor(Date.now() / 1000);
  if (!tsSeconds || Math.abs(nowSeconds - tsSeconds) > 5 * 60) return { valid: false };

  const rawBody = req.rawBody ? req.rawBody.toString('utf8') : JSON.stringify(req.body);
  const signedContent = `${webhookId}.${webhookTimestamp}.${rawBody}`;
  const expectedSignature = crypto.createHmac('sha256', WHOP_WEBHOOK_SECRET).update(signedContent).digest('base64');

  const candidates = signatureHeader.split(' ').map(part => part.split(',')[1]).filter(Boolean);
  const isValid = candidates.some(sig => {
    try {
      return crypto.timingSafeEqual(Buffer.from(sig, 'base64'), Buffer.from(expectedSignature, 'base64'));
    } catch { return false; }
  });

  return { valid: isValid };
}

app.post('/api/whop-webhook', async (req, res) => {
  try {
    const verification = verifyWhopSignature(req);
    if (!verification.valid) return res.status(401).json({ error: 'Invalid signature' });

    const webhookId = req.headers['webhook-id'];
    if (!webhookId) return res.status(400).json({ error: 'Missing webhook ID' });

    const db = await getDb();
    const processedWebhooks = db.collection('processed_webhooks');

    try {
      await processedWebhooks.insertOne({ _id: webhookId, created_at: new Date() });
    } catch (dbErr) {
      if (dbErr.code === 11000) {
        console.warn(`Webhook ${webhookId} already processed (Idempotency skip).`);
        return res.status(200).json({ success: true, note: 'Already processed' });
      }
      throw dbErr;
    }

    const event = req.body;
    const action = event.action || event.type;
    const data = event.data || event;

    if (!data) return res.status(200).json({ received: true });

    const email = (data.user?.email || data.member?.email || data.email || '').toLowerCase();
    const planId = data.plan_id || (data.plan && data.plan.id) || (data.line_items && data.line_items[0]?.plan_id) || '';

    if (!email) return res.status(200).json({ received: true, note: 'No email found' });

    const users = db.collection('users');
    const now = Date.now();

    let durationDays = 30;
    if (planId === 'plan_hhPYAFHhQnZ2p') durationDays = 90;
    else if (planId === 'plan_SFcazKZDf63GC') durationDays = 180;
    else if (planId === 'plan_PJeLIwlopBsLV') durationDays = 365;
    else if (planId === 'plan_1AFMWzPSMlWF7') durationDays = 30;

    const durationMs = durationDays * 24 * 60 * 60 * 1000;

    if (action === 'membership.activated' || action === 'payment.succeeded') {
      const existingUser = await users.findOne({ email });

      let newExpiry = now + durationMs;
      if (existingUser && existingUser.subscription_active && existingUser.expires_at > now) {
        newExpiry = existingUser.expires_at + durationMs;
      }

      await users.updateOne(
        { email },
        {
          $set: {
            subscription_active: true,
            plan: 'PRO',
            started_at: existingUser?.started_at && existingUser.started_at > 0 ? existingUser.started_at : now,
            expires_at: newExpiry,
            whop_id: data.user?.id || data.id || null,
            updated_at: now
          }
        },
        { upsert: true }
      );
    } else if (action === 'membership.deactivated') {
      await users.updateOne(
        { email },
        { $set: { subscription_active: false, plan: 'free', updated_at: now } }
      );
    }

    res.status(200).json({ success: true });
  } catch (err) {
    console.error('Webhook processing error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ==========================================
// مسارات تفعيل الاشتراكات (محمية بـ CSRF)
// ==========================================
app.post('/api/claim-early-bird', csrfCheck, requireAuth, async (req, res) => {
  try {
    const { ageConfirmed } = req.body;
    
    // إقرار المستخدم بأنه فوق 18 عاماً
    if (!ageConfirmed) {
      return res.status(403).json({ error: 'يجب تأكيد أن عمرك 18 عاماً أو أكثر للمتابعة' });
    }

    const email = req.userEmail;
    const db = await getDb();
    const coupons = db.collection('coupons');
    const users = db.collection('users');

    await coupons.updateOne(
      { code: EARLY_BIRD_CODE },
      { 
        $setOnInsert: { 
          max_uses: EARLY_BIRD_MAX_SEATS, 
          used_count: 0, 
          duration_days: EARLY_BIRD_DURATION_DAYS, 
          type: 'free', 
          created_at: Date.now(),
          claimed_by: []
        } 
      },
      { upsert: true }
    );

    const updateResult = await coupons.updateOne(
      { 
        code: EARLY_BIRD_CODE, 
        used_count: { $lt: EARLY_BIRD_MAX_SEATS },
        claimed_by: { $ne: email }
      },
      { 
        $inc: { used_count: 1 },
        $push: { claimed_by: email }
      }
    );

    if (updateResult.modifiedCount === 0) {
      const coupon = await coupons.findOne({ code: EARLY_BIRD_CODE });
      if (coupon && coupon.claimed_by && coupon.claimed_by.includes(email)) {
        return res.status(400).json({ error: 'لقد استخدمت مكافأة أول 15 مستخدم من قبل' });
      }
      return res.status(400).json({ error: 'عذراً، نفدت المقاعد المجانية المتاحة' });
    }

    const now = Date.now();
    const durationMs = EARLY_BIRD_DURATION_DAYS * 24 * 60 * 60 * 1000;
    const existingUser = await users.findOne({ email });
    let newExpiry = now + durationMs;

    if (existingUser && existingUser.subscription_active && existingUser.expires_at > now) {
      newExpiry = existingUser.expires_at + durationMs;
    }

    await users.updateOne(
      { email },
      {
        $set: {
          subscription_active: true,
          plan: 'VIP_PRO',
          started_at: existingUser?.started_at && existingUser.started_at > 0 ? existingUser.started_at : now,
          expires_at: newExpiry,
          early_bird_claimed: true,
          updated_at: now
        }
      }
    );

    res.json({ success: true, message: 'تم تفعيل حساب PRO بنجاح!' });
  } catch (err) {
    res.status(500).json({ error: 'حدث خطأ أثناء التفعيل' });
  }
});

app.post('/api/apply-coupon', csrfCheck, requireAuth, async (req, res) => {
  try {
    const email = req.userEmail;
    const { couponCode } = req.body;
    if (!couponCode) return res.status(400).json({ error: 'يرجى إدخال الكود' });
    const cleanCode = couponCode.trim().toUpperCase();
    if (cleanCode === EARLY_BIRD_CODE) return res.status(400).json({ error: 'كود التفعيل غير صحيح' });

    const db = await getDb();
    const coupons = db.collection('coupons');
    const users = db.collection('users');

    const coupon = await coupons.findOne({ code: cleanCode });
    if (!coupon) return res.status(404).json({ error: 'كود التفعيل غير صحيح' });

    if (coupon.used_count >= coupon.max_uses) {
      return res.status(400).json({ error: 'عذراً، نفدت المقاعد المجانية المتاحة لهذا الكود' });
    }

    const updateResult = await coupons.updateOne(
      { code: cleanCode, used_count: { $lt: coupon.max_uses } },
      { $inc: { used_count: 1 } }
    );

    if (updateResult.modifiedCount === 0) return res.status(400).json({ error: 'عذراً، نفدت المقاعد المجانية المتاحة لهذا الكود' });

    const now = Date.now();
    const durationMs = (coupon.duration_days || 30) * 24 * 60 * 60 * 1000;
    const existingUser = await users.findOne({ email });
    let newExpiry = now + durationMs;

    if (existingUser && existingUser.subscription_active && existingUser.expires_at > now) {
      newExpiry = existingUser.expires_at + durationMs;
    }

    await users.updateOne(
      { email },
      {
        $set: {
          subscription_active: true,
          plan: 'VIP_PRO',
          started_at: existingUser?.started_at && existingUser.started_at > 0 ? existingUser.started_at : now,
          expires_at: newExpiry,
          coupon_used: cleanCode,
          updated_at: now
        }
      }
    );
    res.json({ success: true, type: 'free', message: 'تم تفعيل حساب PRO بنجاح!' });
  } catch (err) { res.status(500).json({ error: 'فشل تطبيق الكود' }); }
});

// ==========================================
// مسارات عرض البيانات (GET لا تحتاج CSRF)
// ==========================================
app.get('/api/promo-stats', async (req, res) => {
  try {
    const db = await getDb();
    const coupon = await db.collection('coupons').findOne({ code: EARLY_BIRD_CODE });
    if (!coupon) return res.json({ active: true, remaining: EARLY_BIRD_MAX_SEATS, currentRank: 1 });

    res.json({
      active: true,
      remaining: Math.max(0, coupon.max_uses - coupon.used_count),
      currentRank: coupon.used_count + 1
    });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch promo stats' });
  }
});

app.get('/api/launch-app', async (req, res) => {
  try {
    const token = req.cookies.token;
    if (!token) return res.redirect('/?error=unauthorized');

    const decoded = jwt.verify(token, JWT_SECRET);
    const db = await getDb();
    const user = await db.collection('users').findOne({ email: decoded.email.toLowerCase() });

    if (!user || !user.subscription_active || user.expires_at <= Date.now()) {
      return res.redirect('/?error=subscription_required');
    }

    res.redirect(TOOL_URL);
  } catch (err) {
    res.redirect('/?error=access_denied');
  }
});

app.get('/api/get-tool-url', requireAuth, async (req, res) => {
  try {
    const db = await getDb();
    const user = await db.collection('users').findOne({ email: req.userEmail });

    if (!user || !user.subscription_active || user.expires_at <= Date.now()) {
      return res.status(403).json({ error: 'Subscription required' });
    }

    const accessToken = jwt.sign({ email: req.userEmail }, JWT_SECRET, { expiresIn: '4h' });
    const separator = TOOL_URL.includes('?') ? '&' : '?';
    const urlWithToken = `${TOOL_URL}${separator}access_token=${accessToken}`;

    res.json({ url: urlWithToken });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ==========================================
// مسارات الحذف وتسجيل الخروج (محمية بـ CSRF)
// ==========================================
app.post('/api/logout', csrfCheck, (req, res) => {
  res.clearCookie('token', { sameSite: isProd ? 'none' : 'lax', secure: isProd });
  res.json({ success: true });
});

app.post('/api/delete-account', csrfCheck, requireAuth, async (req, res) => {
  try {
    const db = await getDb();
    await db.collection('users').deleteOne({ email: req.userEmail });

    res.clearCookie('token', { sameSite: isProd ? 'none' : 'lax', secure: isProd });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Delete failed' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running securely on port ${PORT} (Prod Mode: ${isProd})`);
});

export default app;
