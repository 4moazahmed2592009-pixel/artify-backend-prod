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

// ==========================================
// 1. إعدادات CORS الشاملة لقبول اتصالات Gemini Canvas
// ==========================================
const configuredToolOrigin = (() => {
  try { return new URL(process.env.TOOL_URL || '').origin; } catch { return ''; }
})();

const allowedOrigins = [
  'https://artify-backend-prod.vercel.app',
  'http://localhost:3000',
  configuredToolOrigin
].filter(Boolean);

app.use(cors({
  origin: function (origin, callback) {
    // قبول الطلبات القادمة من Canvas أو النطاقات المعزولة أو لوحة التحكم دون إرجاع خطأ حظر
    if (
      !origin ||
      origin === 'null' ||
      allowedOrigins.indexOf(origin) !== -1 ||
      origin.endsWith('googleusercontent.com') ||
      origin.includes('gemini.google.com')
    ) {
      callback(null, true);
    } else {
      callback(null, true);
    }
  },
  credentials: true
}));

// معالجة طلبات الاستئذان المسبقة (OPTIONS Preflight) لجميع المسارات
app.options('*', cors());

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
const SITE_URL = 'https://artify-backend-prod.vercel.app';

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

function csrfCheck(req, res, next) {
  const csrfHeader = req.headers['x-artify-csrf'];
  if (!csrfHeader || csrfHeader !== '1') {
    return res.status(403).json({ error: 'CSRF token missing or invalid' });
  }
  next();
}

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
// مسارات المصادقة والمستخدم
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
// Webhook الدفع (Whop)
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
// مسارات تفعيل العروض والأكواد
// ==========================================
app.post('/api/claim-early-bird', csrfCheck, requireAuth, async (req, res) => {
  try {
    const { ageConfirmed } = req.body;
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
        $inc: { used_count: 1 },$push: { claimed_by: email }
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

// ==========================================================
// نظام ربط الأجهزة برمز الـ 6 أرقام (Tool Pairing System)
// ==========================================================
const TOOL_CODE_TTL_MS = 10 * 60 * 1000;              // مدة صلاحية الكود: 10 دقائق
const TOOL_SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1000; // صلاحية الجلسة: 30 يوماً
const MAX_TOOL_DEVICES = 2;                           // أقصى عدد أجهزة مسموح بربطها
const TOOL_CODE_LENGTH = 6;
const TOOL_CODE_MAX_ATTEMPTS_PER_WINDOW = 30;
const TOOL_CODE_ATTEMPT_WINDOW_MS = 10 * 60 * 1000;

const hashAccessSecret = (value) => crypto.createHash('sha256').update(String(value)).digest('hex');

function normalizeDeviceId(value) {
  const id = typeof value === 'string' ? value.trim() : '';
  return /^[a-zA-Z0-9_-]{20,120}$/.test(id) ? id : null;
}

function createSixDigitCode() {
  return crypto.randomInt(0, 1000000).toString().padStart(TOOL_CODE_LENGTH, '0');
}

function getClientAddress(req) {
  const forwarded = req.headers['x-forwarded-for'];
  if (typeof forwarded === 'string' && forwarded.trim()) return forwarded.split(',')[0].trim();
  return req.ip || req.socket?.remoteAddress || 'unknown';
}

async function enforceToolCodeRateLimit(req) {
  const db = await getDb();
  const now = Date.now();
  const key = hashAccessSecret(getClientAddress(req));
  const existing = await db.collection('tool_code_rate_limits').findOne({ key });

  if (!existing || Number(existing.reset_at) <= now) {
    await db.collection('tool_code_rate_limits').updateOne(
      { key },
      { $set: { key, attempts: 1, reset_at: now + TOOL_CODE_ATTEMPT_WINDOW_MS } },
      { upsert: true }
    );
    return true;
  }

  if (Number(existing.attempts) >= TOOL_CODE_MAX_ATTEMPTS_PER_WINDOW) return false;

  await db.collection('tool_code_rate_limits').updateOne(
    { key, reset_at: existing.reset_at },
    { $inc: { attempts: 1 } }
  );
  return true;
}

async function createToolLinkCode(email) {
  const db = await getDb();
  const now = Date.now();
  const normalizedEmail = String(email || '').trim().toLowerCase();

  await db.collection('tool_link_codes').deleteMany({
    email: normalizedEmail,
    used_at: null,
  });

  let code = '';
  let codeHash = '';
  for (let attempt = 0; attempt < 5; attempt += 1) {
    code = createSixDigitCode();
    codeHash = hashAccessSecret(code);
    const existing = await db.collection('tool_link_codes').findOne({ code_hash: codeHash });
    if (!existing) break;
    code = '';
    codeHash = '';
  }

  if (!code) throw new Error('Could not generate a unique tool access code');

  const expiresAt = now + TOOL_CODE_TTL_MS;
  await db.collection('tool_link_codes').insertOne({
    email: normalizedEmail,
    code_hash: codeHash,
    created_at: now,
    expires_at: expiresAt,
    used_at: null,
  });

  return { code, expiresAt };
}

async function validateSubscribedUser(email) {
  const db = await getDb();
  const normalizedEmail = String(email || '').trim().toLowerCase();
  const user = await db.collection('users').findOne({ email: normalizedEmail });

  if (!user) return { user: null, reason: 'user_not_found' };
  if (!user.subscription_active) return { user: null, reason: 'subscription_inactive' };
  if (!Number.isFinite(Number(user.expires_at)) || Number(user.expires_at) <= Date.now()) {
    return { user: null, reason: 'subscription_expired' };
  }

  return { user, reason: null };
}

function encryptLaunchCode(code) {
  const key = crypto.createHash('sha256').update(String(JWT_SECRET)).digest();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ciphertext = Buffer.concat([cipher.update(String(code), 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, ciphertext]).toString('base64url');
}

function decryptLaunchCode(payload) {
  const key = crypto.createHash('sha256').update(String(JWT_SECRET)).digest();
  const raw = Buffer.from(String(payload), 'base64url');
  if (raw.length < 29) throw new Error('Invalid launch ticket payload');
  const iv = raw.subarray(0, 12);
  const tag = raw.subarray(12, 28);
  const ciphertext = raw.subarray(28);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8');
}

async function createToolLaunchTicket(email, code, expiresAt) {
  const db = await getDb();
  const ticket = crypto.randomBytes(24).toString('hex');
  await db.collection('tool_launch_tickets').insertOne({
    ticket_hash: hashAccessSecret(ticket),
    email: String(email || '').trim().toLowerCase(),
    code_encrypted: encryptLaunchCode(code),
    expires_at: expiresAt,
    created_at: Date.now(),
    used_at: null,
  });
  return ticket;
}

app.get('/api/launch-app', async (req, res) => {
  try {
    const authToken = req.cookies.token;
    if (!authToken) return res.redirect('/?error=unauthorized');

    const decoded = jwt.verify(authToken, JWT_SECRET);
    const email = typeof decoded?.email === 'string' ? decoded.email.trim().toLowerCase() : '';
    if (!email) return res.redirect('/?error=access_denied');

    const { user } = await validateSubscribedUser(email);
    if (!user) return res.redirect('/?error=subscription_required');

    let code = '';
    let expiresAt = 0;
    const requestedTicket = typeof req.query.ticket === 'string' ? req.query.ticket.trim() : '';

    if (requestedTicket) {
      const db = await getDb();
      const ticketDoc = await db.collection('tool_launch_tickets').findOne({
        ticket_hash: hashAccessSecret(requestedTicket),
        email,
        used_at: null,
      });
      if (!ticketDoc || Number(ticketDoc.expires_at) <= Date.now()) {
        return res.redirect('/?error=access_denied');
      }

      await db.collection('tool_launch_tickets').updateOne(
        { _id: ticketDoc._id, used_at: null },
        { $set: { used_at: Date.now() } }
      );

      code = decryptLaunchCode(ticketDoc.code_encrypted);
      expiresAt = Number(ticketDoc.expires_at);
    } else {
      const created = await createToolLinkCode(email);
      code = created.code;
      expiresAt = created.expiresAt;
    }

    const safeToolUrl = String(TOOL_URL).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    const minutes = Math.max(1, Math.ceil((expiresAt - Date.now()) / 60000));

    res.set('Cache-Control', 'no-store, no-cache, must-revalidate, private');
    res.status(200).send(`<!doctype html>
<html lang="ar" dir="rtl">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width,initial-scale=1" />
<title>ربط Artify PRO</title>
<style>
body{margin:0;background:#030712;color:#fff;font-family:Arial,sans-serif;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px;box-sizing:border-box}
.card{width:min(520px,100%);background:#111827;border:1px solid #374151;border-radius:20px;padding:32px;box-sizing:border-box;text-align:center;box-shadow:0 20px 60px rgba(0,0,0,.45)}
h1{margin:0 0 12px;font-size:28px}.muted{color:#9ca3af;line-height:1.8}.code{font-size:48px;letter-spacing:.28em;font-weight:900;background:#030712;border:1px solid #4f46e5;border-radius:16px;padding:18px 12px;margin:24px 0;direction:ltr}.btn{display:block;text-decoration:none;background:#4f46e5;color:#fff;padding:14px 18px;border-radius:12px;font-weight:800;margin-top:14px}.small{font-size:13px;color:#6b7280;margin-top:16px;line-height:1.7}
</style>
</head>
<body>
<main class="card">
<h1>رمز ربط Artify PRO</h1>
<p class="muted">افتح الأداة ثم أدخل الرمز الظاهر بالأسفل. الرمز صالح لمدة ${minutes} دقائق ويُستخدم مرة واحدة.</p>
<div class="code">${code}</div>
<a class="btn" href="${safeToolUrl}">فتح Artify PRO</a>
<p class="small">لا تشارك هذا الرمز مع أي شخص. إذا انتهت صلاحيته، ارجع للموقع الرئيسي وأنشئ رمزاً جديداً.</p>
</main>
</body>
</html>`);
  } catch (err) {
    console.error('Launch app error:', err);
    return res.redirect('/?error=access_denied');
  }
});

app.get('/api/get-tool-url', requireAuth, async (req, res) => {
  try {
    const { user } = await validateSubscribedUser(req.userEmail);
    if (!user) return res.status(403).json({ error: 'Subscription required' });

    const { code, expiresAt } = await createToolLinkCode(req.userEmail);
    const ticket = await createToolLaunchTicket(req.userEmail, code, expiresAt);
    return res.json({
      url: `${SITE_URL}/api/launch-app?ticket=${encodeURIComponent(ticket)}`,
      code,
      expiresAt,
      expiresInSeconds: Math.max(0, Math.floor((expiresAt - Date.now()) / 1000)),
    });
  } catch (err) {
    console.error('Get tool URL/code error:', err);
    return res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/redeem-tool-code', express.json(), async (req, res) => {
  res.set('Cache-Control', 'no-store');
  try {
    const rawCode = typeof req.body?.code === 'string' ? req.body.code.replace(/\D/g, '') : '';
    const deviceId = normalizeDeviceId(req.body?.deviceId);

    if (!(await enforceToolCodeRateLimit(req))) {
      return res.status(429).json({ valid: false, reason: 'too_many_attempts', message: 'محاولات كثيرة. انتظر عدة دقائق ثم حاول مرة أخرى.' });
    }

    if (!/^\d{6}$/.test(rawCode)) {
      return res.status(400).json({ valid: false, reason: 'invalid_code_format', message: 'رمز الربط يجب أن يتكون من 6 أرقام.' });
    }
    if (!deviceId) {
      return res.status(400).json({ valid: false, reason: 'invalid_device_id', message: 'معرّف الجهاز غير صالح.' });
    }

    const db = await getDb();
    const now = Date.now();
    const codeHash = hashAccessSecret(rawCode);
    const link = await db.collection('tool_link_codes').findOne({ code_hash: codeHash });

    if (!link || link.used_at || Number(link.expires_at) <= now) {
      return res.status(200).json({ valid: false, reason: 'invalid_or_expired_code', message: 'رمز الربط غير صالح أو منتهي أو تم استخدامه بالفعل.' });
    }

    const { user, reason } = await validateSubscribedUser(link.email);
    if (!user) {
      return res.status(200).json({ valid: false, reason, message: 'لا يوجد اشتراك نشط لهذا الحساب.' });
    }

    const currentDevices = Array.isArray(user.devices) ? user.devices : [];
    const existingDevice = currentDevices.some((d) => d && d.device_id === deviceId);

    if (!existingDevice && currentDevices.length >= MAX_TOOL_DEVICES) {
      return res.status(200).json({
        valid: false,
        reason: 'device_limit_reached',
        message: 'تم الوصول إلى الحد الأقصى وهو جهازان. سجّل الخروج من جميع الأجهزة من الموقع ثم اربط هذا الجهاز.',
      });
    }

    const consumed = await db.collection('tool_link_codes').findOneAndUpdate(
      { _id: link._id, used_at: null, expires_at: { $gt: now } },
      { $set: { used_at: now, used_device_id: deviceId } },
      { returnDocument: 'after', includeResultMetadata: true }
    );

    if (!consumed.value) {
      return res.status(200).json({ valid: false, reason: 'code_already_used', message: 'تم استخدام رمز الربط بالفعل. اطلب رمزاً جديداً.' });
    }

    const updatedDevices = existingDevice
      ? currentDevices.map((d) => d && d.device_id === deviceId ? { ...d, last_seen_at: now } : d)
      : [...currentDevices, { device_id: deviceId, created_at: now, last_seen_at: now }];

    await db.collection('users').updateOne(
      { _id: user._id },
      { $set: { devices: updatedDevices } }
    );

    const sessionToken = crypto.randomBytes(32).toString('hex');
    const sessionExpiresAt = Math.min(Number(user.expires_at), now + TOOL_SESSION_TTL_MS);

    await db.collection('tool_sessions').insertOne({
      token_hash: hashAccessSecret(sessionToken),
      email: link.email,
      device_id: deviceId,
      created_at: now,
      last_seen_at: now,
      expires_at: sessionExpiresAt,
      revoked_at: null,
    });

    return res.status(200).json({
      valid: true,
      sessionToken,
      expiresAt: sessionExpiresAt,
    });
  } catch (err) {
    console.error('Redeem tool code error:', err);
    return res.status(500).json({ valid: false, reason: 'server_error', message: 'حدث خطأ داخلي أثناء ربط الجهاز.' });
  }
});

app.post('/api/verify-tool-session', express.json(), async (req, res) => {
  res.set('Cache-Control', 'no-store');
  try {
    const sessionToken = typeof req.body?.sessionToken === 'string' ? req.body.sessionToken.trim() : '';
    const deviceId = normalizeDeviceId(req.body?.deviceId);
    if (!sessionToken || !deviceId) {
      return res.status(400).json({ valid: false, reason: 'missing_session_data' });
    }

    const db = await getDb();
    const now = Date.now();
    const session = await db.collection('tool_sessions').findOne({
      token_hash: hashAccessSecret(sessionToken),
      device_id: deviceId,
      revoked_at: null,
    });

    if (!session || Number(session.expires_at) <= now) {
      return res.status(200).json({ valid: false, reason: 'session_expired' });
    }

    const { user, reason } = await validateSubscribedUser(session.email);
    if (!user) {
      return res.status(200).json({ valid: false, reason, message: 'الاشتراك غير نشط.' });
    }

    const deviceExists = (Array.isArray(user.devices) ? user.devices : []).some((d) => d && d.device_id === deviceId);
    if (!deviceExists) {
      return res.status(200).json({ valid: false, reason: 'device_revoked' });
    }

    await db.collection('tool_sessions').updateOne(
      { _id: session._id },
      { $set: { last_seen_at: now } }
    );
    await db.collection('users').updateOne(
      { _id: user._id, 'devices.device_id': deviceId },
      { $set: { 'devices.$.last_seen_at': now } }
    );

    return res.status(200).json({ valid: true, expiresAt: Number(session.expires_at) });
  } catch (err) {
    console.error('Verify tool session error:', err);
    return res.status(500).json({ valid: false, reason: 'server_error' });
  }
});

app.post('/api/revoke-tool-devices', csrfCheck, requireAuth, async (req, res) => {
  try {
    const db = await getDb();
    await db.collection('tool_sessions').deleteMany({ email: req.userEmail });
    await db.collection('users').updateOne(
      { email: req.userEmail },
      { $set: { devices: [] } }
    );
    return res.json({ success: true });
  } catch (err) {
    console.error('Revoke tool devices error:', err);
    return res.status(500).json({ error: 'Failed to revoke tool devices' });
  }
});

// ==========================================
// مسارات الحساب وتسجيل الخروج
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
