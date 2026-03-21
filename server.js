// ============================================================
//  RouteRide Bus Booking — Complete Production Server
//  Stack: Node.js + Express + PostgreSQL + Redis + Hesabe +
//         Twilio WhatsApp + SendGrid Email
//
//  File structure expected:
//    /routeride-backend
//      server.js          
//← this file
//      hesabeCrypt.js     
//      .env               
//      package.json
//← encryption helper (below)
//← environment variables
// ============================================================
'use strict';
require('dotenv').config();
const express       = require('express');
const cors          = require('cors');
const helmet        = require('helmet');
const rateLimit     = require('express-rate-limit');
const { Pool }      = require('pg');
const Redis         = require('ioredis');
const Razorpay      = require('razorpay');   // kept for fallback
const axios         = require('axios');
const bcrypt        = require('bcryptjs');
const jwt           = require('jsonwebtoken');
const sgMail        = require('@sendgrid/mail');
const twilio        = require('twilio');
const HesabeCrypt   = require('./hesabeCrypt');
// ─── App init ────────────────────────────────────────────────
const app  = express();
const PORT = process.env.PORT || 3000;
// ─── Database (PostgreSQL via Supabase / Railway) ─────────────
const db = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DB_SSL === 'false'
    ? false
    : { rejectUnauthorized: false },
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 5000,
});
// Test DB connection on startup
db.connect()
  .then(client => { console.log(' PostgreSQL connected'); client.release(); })
  .catch(err   => console.error(' PostgreSQL connection error:', err.message));
// ─── Redis (Upstash or Railway Redis) ─────────────────────────
const redis = new Redis(process.env.REDIS_URL, {
  maxRetriesPerRequest: 3,
  lazyConnect: true,
});
redis.on('connect', () => console.log(' Redis connected'));
redis.on('error',   e  => console.error(' Redis error:', e.message));
// ─── Hesabe Payment Gateway (Kuwait) ──────────────────────────
const hesabeCrypt   = new HesabeCrypt(
  process.env.HESABE_SECRET_KEY,
  process.env.HESABE_IV_KEY
);
const HESABE_IS_PROD    = process.env.HESABE_ENV === 'production';
const HESABE_CHECKOUT   = HESABE_IS_PROD
  ? 'https://api.hesabe.com/checkout'
  : 'https://sandbox.hesabe.com/checkout';
const HESABE_PAYMENT_URL = HESABE_IS_PROD
  ? 'https://api.hesabe.com/payment'
  : 'https://sandbox.hesabe.com/payment';
// ─── Twilio WhatsApp ───────────────────────────────────────────
const twilioClient = twilio(
  process.env.TWILIO_ACCOUNT_SID,
  process.env.TWILIO_AUTH_TOKEN
);
// ─── SendGrid Email ────────────────────────────────────────────
sgMail.setApiKey(process.env.SENDGRID_API_KEY);
// ============================================================
// MIDDLEWARE
// ============================================================
// Security headers
app.use(helmet());
// CORS — allow your frontend domain
app.use(cors({
  origin: [
    process.env.FRONTEND_URL,
	'https://captain-tour-travels.vercel.app',
    'http://localhost:3000',
    'http://localhost:5173',
  ].filter(Boolean),
  credentials: true,
}));
// Body parsers — NOTE: webhook route needs raw body
app.use((req, res, next) => {
  if (req.path === '/api/payments/hesabe/webhook') {
    express.raw({ type: 'application/json' })(req, res, next);
  } else {
    express.json({ limit: '10kb' })(req, res, next);
  }
});
// Rate limiting — general
app.use('/api/', rateLimit({
  windowMs: 15 * 60 * 1000,   // 15 minutes
  max:      200,
  message:  { error: 'Too many requests, please try again later.' },
}));
// Rate limiting — stricter for payment endpoints
app.use('/api/payments/', rateLimit({
  windowMs: 15 * 60 * 1000,
  max:      30,
  message:  { error: 'Too many payment requests.' },
}));
// Request logger
app.use((req, _res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.path}`);
  next();
});
// ============================================================
// HELPERS
// ============================================================
// Generate booking reference: RR-2025-XXXXX
function generateBookingRef() {
  const year = new Date().getFullYear();
  const rand = Math.floor(10000 + Math.random() * 90000);
  return `RR-${year}-${rand}`;
}
// Format KWD amount (3 decimal places)
function formatKWD(amount) {
  return parseFloat(amount).toFixed(3);
}
// Standard error response
function sendError(res, status, message, details = null) {
  const body = { success: false, error: message };
  if (details && process.env.NODE_ENV !== 'production') body.details = details;
  return res.status(status).json(body);
}
// ─── JWT Auth middleware ───────────────────────────────────────
function requireAuth(req, res, next) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith('Bearer '))
    return sendError(res, 401, 'Authentication required');
  try {
    req.user = jwt.verify(header.slice(7), process.env.JWT_SECRET);
    next();
  } catch {
    return sendError(res, 401, 'Invalid or expired token');
  }
}
// ─── Admin auth middleware ─────────────────────────────────────
function requireAdmin(req, res, next) {
  requireAuth(req, res, () => {
    if (!['ADMIN', 'SUPER_ADMIN'].includes(req.user.role))
      return sendError(res, 403, 'Admin access required');
    next();
  });
}
// ─── Release expired seat locks ────────────────────────────────
async function releaseExpiredLocks() {
  try {
    const result = await db.query(
      `UPDATE seats
       SET status = 'AVAILABLE', locked_until = NULL, locked_by = NULL
       WHERE status = 'LOCKED' AND locked_until < NOW()`
    );
    if (result.rowCount > 0)
      console.log(` Released ${result.rowCount} expired seat lock(s)`);
  } catch (err) {
    console.error('Lock expiry error:', err.message);
  }
}
// Run every 2 minutes
setInterval(releaseExpiredLocks, 2 * 60 * 1000);
// ============================================================
// ─── NOTIFICATION HELPERS ────────────────────────────────────
// ============================================================
// ─── WhatsApp via Twilio ───────────────────────────────────────
async function sendWhatsApp(phone, message, bookingId = null, scheduleId = null, template = 'ticket_confirmed') {
  try {
    const to = phone.startsWith('+') ? `whatsapp:${phone}` : `whatsapp:+965${phone}`;
    const msg = await twilioClient.messages.create({
      from: process.env.TWILIO_WHATSAPP_FROM,
      to,
      body: message,
    });
    await db.query(
      `INSERT INTO notification_log
         (booking_id, schedule_id, recipient_phone, type, template_name, message_body, status, provider_msg_id)
       VALUES ($1,$2,$3,'WHATSAPP',$4,$5,'SENT',$6)`,
      [bookingId, scheduleId, phone, template, message, msg.sid]
    );
    return { success: true, sid: msg.sid };
  } catch (err) {
    console.error('WhatsApp error:', err.message);
    await db.query(
      `INSERT INTO notification_log
         (booking_id, schedule_id, recipient_phone, type, template_name, message_body, status, error_message)
       VALUES ($1,$2,$3,'WHATSAPP',$4,$5,'FAILED',$6)`,
      [bookingId, scheduleId, phone, template, message, err.message]
    );
    return { success: false, error: err.message };
  }
}
// ─── Email via SendGrid ────────────────────────────────────────
async function sendTicketEmail(booking) {
  try {
    const dep = new Date(booking.departure_time)
      .toLocaleString('en-KW', { timeZone: 'Asia/Kuwait', dateStyle: 'medium', timeStyle: 'short' });
    const html = `
<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;background:#f5f0e8;font-family:Arial,sans-serif">
  <div style="max-width:560px;margin:0 auto;background:#fff">
    <!-- Header -->
    <div style="background:#0d1117;padding:28px 32px;text-align:center">
      <h1 style="color:#00c48c;margin:0;font-size:1.8rem;letter-spacing:2px">RouteRide</h1>
      <p style="color:#555;margin:4px 0 0;font-size:0.82rem">Kuwait Bus Ticketing</p>
    </div>
    <!-- Ticket body -->
    <div style="padding:28px 32px">
      <p style="color:#333;font-size:0.95rem;margin-bottom:20px">
        Dear <strong>${booking.first_name} ${booking.last_name || ''}</strong>,<br>
        Your booking is confirmed! Here are your travel details:
      </p>
      <!-- Booking Ref -->
      <div style="background:#f9f6f0;border:2px dashed #e0d8c8;border-radius:10px;padding:18px;text-align:center;margin-bottom:22px">
        <div style="font-size:0.7rem;color:#888;letter-spacing:2px;text-transform:uppercase;margin-bottom:6px">BOOKING REFERENCE</div>
        <div style="font-size:1.8rem;font-weight:800;color:#c94b2c;letter-spacing:3px">${booking.booking_ref}</div>
        <div style="font-size:0.78rem;color:#888;margin-top:5px">Show this at the boarding point</div>
      </div>
      <!-- Details table -->
      <table style="width:100%;border-collapse:collapse;font-size:0.88rem">
        <tr style="border-bottom:1px solid #eee">
          <td style="padding:10px 0;color:#888;width:40%">Bus Operator</td>
          <td style="padding:10px 0;font-weight:600">${booking.operator_name}</td>
        </tr>
        <tr style="border-bottom:1px solid #eee">
          <td style="padding:10px 0;color:#888">Route</td>
          <td style="padding:10px 0;font-weight:600">${booking.origin_city} → ${booking.destination_city}</td>
        </tr>
        <tr style="border-bottom:1px solid #eee">
          <td style="padding:10px 0;color:#888">Departure</td>
          <td style="padding:10px 0;font-weight:600">${dep}</td>
        </tr>
        <tr style="border-bottom:1px solid #eee">
          <td style="padding:10px 0;color:#888">Seats</td>
          <td style="padding:10px 0;font-weight:600">${booking.seat_numbers.join(', ')}</td>
        </tr>
        <tr style="border-bottom:1px solid #eee">
          <td style="padding:10px 0;color:#888">Payment Method</td>
          <td style="padding:10px 0;font-weight:600">${getPaymentMethodName(booking.hesabe_method)}</td>
        </tr>
        <tr>
          <td style="padding:12px 0;color:#888;font-weight:600">Amount Paid</td>
          <td style="padding:12px 0;font-weight:800;font-size:1.1rem;color:#009b77">
            KWD ${formatKWD(booking.total_amount)}
          </td>
        </tr>
      </table>
    </div>
    <!-- Pickup info -->
    <div style="background:#e8f5ef;padding:16px 32px;border-top:2px solid #00c48c">
      <p style="margin:0;font-size:0.82rem;color:#1a5a35">
 <strong>Please arrive 15 minutes before departure</strong> at your pickup point.
        Carry a valid Kuwait Civil ID or Iqama for boarding.
      </p>
    </div>
    <!-- Footer -->
    <div style="background:#0d1117;padding:16px 32px;text-align:center">
      <p style="margin:0;color:#444;font-size:0.75rem">
        RouteRide Kuwait · support@routeride.kw<br>
        <a href="${process.env.FRONTEND_URL}/ticket/${booking.booking_ref}"
           style="color:#00c48c">View ticket online</a>
      </p>
    </div>
  </div>
</body>
</html>`;
    await sgMail.send({
      to:      booking.email,
      from:    { email: process.env.SENDGRID_FROM_EMAIL, name: 'RouteRide Kuwait' },
      subject: ` Booking Confirmed — ${booking.booking_ref} | ${booking.origin_city} → ${booking.destination_city}`,
      html,
    });
    await db.query(
      `INSERT INTO notification_log
         (booking_id, recipient_email, type, template_name, status)
       VALUES ($1,$2,'EMAIL','ticket_confirmed','SENT')`,
      [booking.booking_id, booking.email]
    );
    return { success: true };
  } catch (err) {
    console.error('Email error:', err.message);
    await db.query(
      `INSERT INTO notification_log
         (booking_id, recipient_email, type, template_name, status, error_message)
       VALUES ($1,$2,'EMAIL','ticket_confirmed','FAILED',$3)`,
      [booking.booking_id, booking.email, err.message]
    );
    return { success: false, error: err.message };
  }
}
// Payment method label
function getPaymentMethodName(method) {
  const methods = { 1: 'KNET', 2: 'Visa/Mastercard', 3: 'American Express', 10: 'Apple Pay', 16: 'Google Pay', 18: 'Deema' };
  return methods[method] || 'Online Payment';
}
// ─── Send all ticket notifications after payment ───────────────
async function sendTicketNotifications(bookingId) {
  try {
    const result = await db.query(
      `SELECT * FROM v_booking_details WHERE booking_id = $1`,
      [bookingId]
    );
    if (!result.rows.length) return;
    const booking = result.rows[0];
    const dep = new Date(booking.departure_time)
      .toLocaleString('en-KW', { timeZone: 'Asia/Kuwait', dateStyle: 'medium', timeStyle: 'short' });
    const waMsg =
` *Booking Confirmed — RouteRide*
 Ref: *${booking.booking_ref}*
 ${booking.operator_name}
 ${booking.origin_city} → ${booking.destination_city}
 Departure: ${dep}
 Seats: ${booking.seat_numbers.join(', ')}
 Paid: KWD ${formatKWD(booking.total_amount)}
 Show this message or your booking ref at boarding.
Safe travels! `;
    const promises = [];
    if (booking.notify_whatsapp && booking.phone) {
      promises.push(sendWhatsApp(booking.phone, waMsg, booking.booking_id, null, 'ticket_confirmed'));
    }
    if (booking.notify_email && booking.email) {
      promises.push(sendTicketEmail(booking));
    }
    await Promise.allSettled(promises);
    console.log(` Notifications sent for booking ${booking.booking_ref}`);
  } catch (err) {
    console.error('Notification error:', err.message);
  }
}
// ─── Send bulk trip alert to all passengers ────────────────────
async function sendTripAlert(scheduleId, alertType, message, adminId = null) {
  try {
    const passengers = await db.query(
      `SELECT DISTINCT p.phone, p.email, b.booking_ref, b.id as booking_id,
              b.notify_whatsapp, b.notify_email
       FROM passengers p
       JOIN bookings b ON p.booking_id = b.id
       WHERE b.schedule_id = $1
         AND b.payment_status = 'PAID'
         AND p.is_primary = TRUE`,
      [scheduleId]
    );
    const icons = {
      DELAY:           ' ',
      CANCELLATION:    ' ',
      PICKUP_CHANGE:   ' ',
      SCHEDULE_CHANGE: ' ',
      REMINDER:        ' ',
      GENERAL:         ' ',
    };
    const icon = icons[alertType] || ' ';
    const alertMsg =
`${icon} *RouteRide Alert*
*${alertType.replace('_', ' ')}*
${message}
Booking: {BOOKING_REF}
For help: support@routeride.kw`;
    let sent = 0;
    let failed = 0;
    for (const p of passengers.rows) {
      const personalMsg = alertMsg.replace('{BOOKING_REF}', p.booking_ref);
      const results = await Promise.allSettled([
        p.notify_whatsapp && p.phone
          ? sendWhatsApp(p.phone, personalMsg, p.booking_id, scheduleId, 'trip_alert')
          : Promise.resolve(),
      ]);
      results.forEach(r => r.status === 'fulfilled' ? sent++ : failed++);
    }
    // Log the alert
    await db.query(
      `INSERT INTO trip_alerts (schedule_id, alert_type, message, sent_by_admin, total_sent, total_failed)
       VALUES ($1,$2,$3,$4,$5,$6)`,
      [scheduleId, alertType, message, adminId, sent, failed]
    );
    console.log(` Trip alert sent: ${sent} succeeded, ${failed} failed`);
    return { sent, failed, total: passengers.rows.length };
  } catch (err) {
    console.error('Trip alert error:', err.message);
    throw err;
  }
}
// ============================================================
// ─── ROUTES: HEALTH ──────────────────────────────────────────
// ============================================================
app.get('/', (_req, res) => res.json({
  service: 'RouteRide API',
  version: '1.0.0',
  status:  'running',
  time:    new Date().toISOString(),
}));
app.get('/health', async (_req, res) => {
  let dbOk = false;
  let redisOk = false;
  try { await db.query('SELECT 1'); dbOk = true; } catch {}
  try { await redis.ping(); redisOk = true; } catch {}
  res.json({ db: dbOk, redis: redisOk, uptime: process.uptime() });
});
// ============================================================
// ─── ROUTES: AUTH ────────────────────────────────────────────
// ============================================================
// Admin login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return sendError(res, 400, 'Email and password required');
    const result = await db.query(
      `SELECT id, email, password_hash, full_name, role, operator_id, is_active
       FROM admin_users WHERE email = $1`,
      [email.toLowerCase().trim()]
    );
    const user = result.rows[0];
    if (!user || !user.is_active)
      return sendError(res, 401, 'Invalid credentials');
    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) return sendError(res, 401, 'Invalid credentials');
    // Update last login
    await db.query(`UPDATE admin_users SET last_login_at = NOW() WHERE id = $1`, [user.id]);
    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role, operator_id: user.operator_id },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );
    res.json({ success: true, token, user: { id: user.id, email: user.email, name: user.full_name, role: user.role } });
  } catch (err) {
    sendError(res, 500, 'Login failed', err.message);
  }
});
// ============================================================
// ─── ROUTES: SEARCH ──────────────────────────────────────────
// ============================================================
// Search available buses
// GET /api/buses/search?from=Kuwait+City&to=Ahmadi&date=2025-03-20
app.get('/api/buses/search', async (req, res) => {
  try {
    const { from, to, date } = req.query;
    if (!from || !to || !date) return sendError(res, 400, 'from, to, and date are required');
    // Release any expired locks first
    await releaseExpiredLocks();
    const result = await db.query(
      `SELECT * FROM v_available_schedules
       WHERE origin_city      ILIKE $1
         AND destination_city ILIKE $2
         AND DATE(departure_time AT TIME ZONE 'Asia/Kuwait') = $3::DATE
       ORDER BY departure_time`,
      [`%${from.trim()}%`, `%${to.trim()}%`, date]
    );
    res.json({ success: true, count: result.rows.length, results: result.rows });
  } catch (err) {
    sendError(res, 500, 'Search failed', err.message);
  }
});
// Get all cities (for autocomplete)
app.get('/api/cities', async (_req, res) => {
  try {
    const result = await db.query(
      `SELECT DISTINCT origin_city AS city FROM routes WHERE is_active = TRUE
       UNION
       SELECT DISTINCT destination_city AS city FROM routes WHERE is_active = TRUE
       ORDER BY city`
    );
    res.json({ success: true, cities: result.rows.map(r => r.city) });
  } catch (err) {
    sendError(res, 500, 'Could not fetch cities', err.message);
  }
});
// ============================================================
// ─── ROUTES: SEATS ───────────────────────────────────────────
// ============================================================
// Get real-time seat map for a schedule
// GET /api/schedules/:id/seats
app.get('/api/schedules/:id/seats', async (req, res) => {
  try {
    await releaseExpiredLocks();
    const result = await db.query(
      `SELECT id, seat_number, seat_type, status, price, locked_until
       FROM seats
       WHERE schedule_id = $1
       ORDER BY CAST(seat_number AS INTEGER)`,
      [req.params.id]
    );
    if (!result.rows.length)
      return sendError(res, 404, 'Schedule not found');
    // Mask locked_until from expired locks
    const seats = result.rows.map(s => ({
      ...s,
      locked_until: s.status === 'LOCKED' ? s.locked_until : null,
    }));
    res.json({ success: true, seats });
  } catch (err) {
    sendError(res, 500, 'Could not fetch seats', err.message);
  }
});
// Lock seats (10-minute reservation before payment)
// POST /api/seats/lock
// Body: { schedule_id, seat_numbers: ['1','2'], session_token }
app.post('/api/seats/lock', async (req, res) => {
  const { schedule_id, seat_numbers, session_token } = req.body;
  if (!schedule_id || !Array.isArray(seat_numbers) || !seat_numbers.length || !session_token)
    return sendError(res, 400, 'schedule_id, seat_numbers array, and session_token required');
  if (seat_numbers.length > 6)
    return sendError(res, 400, 'Maximum 6 seats per booking');
  const client = await db.connect();
  try {
    await client.query('BEGIN');
    // Check all seats are available
    const checkResult = await client.query(
      `SELECT seat_number, status FROM seats
       WHERE schedule_id = $1 AND seat_number = ANY($2)
       FOR UPDATE`,
      [schedule_id, seat_numbers]
    );
    if (checkResult.rows.length !== seat_numbers.length)
      throw new Error('One or more seats not found');
    const unavailable = checkResult.rows.filter(s => s.status !== 'AVAILABLE');
    if (unavailable.length > 0) {
      await client.query('ROLLBACK');
      return res.status(409).json({
        success:     false,
        error:       'Some seats are no longer available',
        unavailable: unavailable.map(s => s.seat_number),
      });
    }
    // Lock the seats
    const LOCK_MINUTES = 10;
    const lockExpiry   = new Date(Date.now() + LOCK_MINUTES * 60 * 1000);
    await client.query(
      `UPDATE seats
       SET status = 'LOCKED', locked_until = $1, locked_by = $2
       WHERE schedule_id = $3 AND seat_number = ANY($4)`,
      [lockExpiry, session_token, schedule_id, seat_numbers]
    );
    // Also store in Redis as secondary TTL guard
    const pipeline = redis.pipeline();
    seat_numbers.forEach(s => {
      pipeline.set(`seat:${schedule_id}:${s}`, session_token, 'EX', LOCK_MINUTES * 60, 'NX');
    });
    await pipeline.exec();
    await client.query('COMMIT');
    res.json({ success: true, locked: seat_numbers, expires_at: lockExpiry.toISOString() });
  } catch (err) {
    await client.query('ROLLBACK');
    sendError(res, 500, 'Could not lock seats', err.message);
  } finally {
    client.release();
  }
});
// Release seats (if user goes back / cancels before paying)
// POST /api/seats/release
app.post('/api/seats/release', async (req, res) => {
  const { schedule_id, seat_numbers, session_token } = req.body;
  if (!schedule_id || !Array.isArray(seat_numbers) || !session_token)
    return sendError(res, 400, 'schedule_id, seat_numbers, and session_token required');
  try {
    await db.query(
      `UPDATE seats
       SET status = 'AVAILABLE', locked_until = NULL, locked_by = NULL
       WHERE schedule_id = $1
         AND seat_number = ANY($2)
         AND locked_by   = $3
         AND status      = 'LOCKED'`,
      [schedule_id, seat_numbers, session_token]
    );
    // Remove Redis locks
    const pipeline = redis.pipeline();
    seat_numbers.forEach(s => pipeline.del(`seat:${schedule_id}:${s}`));
    await pipeline.exec();
    res.json({ success: true });
  } catch (err) {
    sendError(res, 500, 'Could not release seats', err.message);
  }
});
// ============================================================
// ─── ROUTES: BOOKINGS ────────────────────────────────────────
// ============================================================
// Create a booking (before payment)
// POST /api/bookings/create
app.post('/api/bookings/create', async (req, res) => {
  const {
    schedule_id,
    seat_numbers,
    passengers: passengerData,
    session_token,
    notify_whatsapp = true,
    notify_email    = true,
  } = req.body;
  if (!schedule_id || !seat_numbers?.length || !passengerData?.length || !session_token)
    return sendError(res, 400, 'schedule_id, seat_numbers, passengers, and session_token required');
  const client = await db.connect();
  try {
    await client.query('BEGIN');
    // Verify seats are still locked by this session
    const seatsResult = await client.query(
      `SELECT id, seat_number, price, status, locked_by
       FROM seats
       WHERE schedule_id = $1 AND seat_number = ANY($2)
       FOR UPDATE`,
      [schedule_id, seat_numbers]
    );
    if (seatsResult.rows.length !== seat_numbers.length)
      throw new Error('Seat count mismatch');
    for (const seat of seatsResult.rows) {
      if (seat.status !== 'LOCKED' || seat.locked_by !== session_token)
        throw new Error(`Seat ${seat.seat_number} lock expired or belongs to another session`);
    }
    // Calculate totals (KWD)
    const baseAmount = seatsResult.rows.reduce((sum, s) => sum + parseFloat(s.price), 0);
    const taxAmount  = Math.round(baseAmount * 0.05 * 1000) / 1000;
    const totalAmount = Math.round((baseAmount + taxAmount) * 1000) / 1000;
    // Generate unique booking ref
    let bookingRef;
    let attempts = 0;
    do {
      bookingRef = generateBookingRef();
      const exists = await client.query('SELECT 1 FROM bookings WHERE booking_ref = $1', [bookingRef]);
      if (!exists.rows.length) break;
    } while (++attempts < 10);
    // Insert booking
    const bookingResult = await client.query(
      `INSERT INTO bookings
         (booking_ref, schedule_id, num_seats, base_amount, tax_amount, total_amount,
          currency, notify_whatsapp, notify_email)
       VALUES ($1,$2,$3,$4,$5,$6,'KWD',$7,$8)
       RETURNING *`,
      [bookingRef, schedule_id, seat_numbers.length, formatKWD(baseAmount),
       formatKWD(taxAmount), formatKWD(totalAmount), notify_whatsapp, notify_email]
    );
    const booking = bookingResult.rows[0];
    // Insert passengers
    const seatMap = {};
    seatsResult.rows.forEach(s => { seatMap[s.seat_number] = s.id; });
    for (let i = 0; i < passengerData.length; i++) {
      const p    = passengerData[i];
      const sNum = seat_numbers[i];
      await client.query(
        `INSERT INTO passengers
           (booking_id, seat_id, is_primary, first_name, last_name,
            age, gender, phone, email, nationality)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
        [booking.id, seatMap[sNum], i === 0,
         p.first_name, p.last_name || null,
         p.age || null, p.gender || null,
         i === 0 ? p.phone : null,
         i === 0 ? p.email : null,
         p.nationality || null]
      );
    }
    await client.query('COMMIT');
    res.status(201).json({
      success:       true,
      booking_id:    booking.id,
      booking_ref:   bookingRef,
      base_amount:   formatKWD(baseAmount),
      tax_amount:    formatKWD(taxAmount),
      total_amount:  formatKWD(totalAmount),
      currency:      'KWD',
    });
  } catch (err) {
    await client.query('ROLLBACK');
    sendError(res, 400, err.message || 'Booking creation failed', err.message);
  } finally {
    client.release();
  }
});
// Get booking by reference
// GET /api/bookings/:ref
app.get('/api/bookings/:ref', async (req, res) => {
  try {
    const result = await db.query(
      `SELECT * FROM v_booking_details WHERE booking_ref = $1`,
      [req.params.ref.toUpperCase()]
    );
    if (!result.rows.length)
      return sendError(res, 404, 'Booking not found');
    res.json({ success: true, booking: result.rows[0] });
  } catch (err) {
    sendError(res, 500, 'Could not fetch booking', err.message);
  }
});
// ============================================================
// ─── ROUTES: HESABE PAYMENT ──────────────────────────────────
// ============================================================
// Step 1: Initiate payment — create Hesabe checkout session
// POST /api/payments/hesabe/initiate
app.post('/api/payments/hesabe/initiate', async (req, res) => {
  try {
    const {
      booking_ref,
      passenger_name,
      passenger_email,
      passenger_phone,
    } = req.body;
    if (!booking_ref) return sendError(res, 400, 'booking_ref required');
    // Fetch the booking
    const bookingResult = await db.query(
      `SELECT id, total_amount, payment_status FROM bookings WHERE booking_ref = $1`,
      [booking_ref.toUpperCase()]
    );
    if (!bookingResult.rows.length)
      return sendError(res, 404, 'Booking not found');
    const booking = bookingResult.rows[0];
    if (booking.payment_status === 'PAID')
      return sendError(res, 409, 'Booking is already paid');
    const payload = {
      merchantCode:         process.env.HESABE_MERCHANT_CODE,
      amount:               formatKWD(booking.total_amount),
      currency:             'KWD',
      paymentType:          0,         // 0 = indirect (hosted page)
      version:              '2.0',
      orderReferenceNumber: booking_ref,
      responseUrl:          `${process.env.APP_URL}/api/payments/hesabe/success`,
      failureUrl:           `${process.env.APP_URL}/api/payments/hesabe/failure`,
      webhookUrl:           `${process.env.APP_URL}/api/payments/hesabe/webhook`,
      name:                 passenger_name  || '',
      email:                passenger_email || '',
      mobile_number:        (passenger_phone || '').replace(/\D/g, '').slice(-8),
      variable1:            booking_ref,
      variable2:            booking.id,
    };
    // Encrypt and send to Hesabe
    const encryptedData = hesabeCrypt.encrypt(JSON.stringify(payload));
    const response = await axios.post(
      HESABE_CHECKOUT,
      { data: encryptedData },
      {
        headers: {
          accessCode:     process.env.HESABE_ACCESS_CODE,
          'Content-Type': 'application/json',
          Accept:         'application/json',
        },
        timeout: 15000,
      }
    );
    // Decrypt Hesabe's response
    const rawResponse     = response.data?.response || response.data;
    const decryptedResponse = hesabeCrypt.decrypt(
      typeof rawResponse === 'string' ? rawResponse : JSON.stringify(rawResponse)
    );
    if (!decryptedResponse?.response?.data)
      throw new Error('Invalid response from Hesabe checkout');
    const paymentToken  = decryptedResponse.response.data;
    const redirectUrl   = `${HESABE_PAYMENT_URL}?data=${paymentToken}`;
    // Save the payment token against the booking
    await db.query(
      `UPDATE bookings
       SET hesabe_payment_token = $1, payment_status = 'PENDING', updated_at = NOW()
       WHERE id = $2`,
      [paymentToken, booking.id]
    );
    // Log raw webhook data
    await db.query(
      `INSERT INTO payment_webhook_log
         (booking_ref, raw_payload, result_code, processed)
       VALUES ($1,$2,'INITIATED',FALSE)`,
      [booking_ref, JSON.stringify(payload)]
    );
    res.json({ success: true, redirectUrl, paymentToken, booking_ref });
  } catch (err) {
    console.error('Hesabe initiate error:', err.response?.data || err.message);
    sendError(res, 500, 'Payment initiation failed', err.message);
  }
});
// Step 2: Success callback — Hesabe redirects here after payment
/ Handles both GET and POST (Hesabe may use either)
async function handleHesabeSuccess(req, res) {
  const FRONTEND = (process.env.FRONTEND_URL || '').replace(/\/+$/, '');
  let bookingRef = null;
  if (!FRONTEND) {
    console.error(' FRONTEND_URL not set — cannot redirect passenger after success');
    return res.status(500).send(
      'Server configuration error: FRONTEND_URL not set. ' +
      'Your payment MAY have been processed. Please contact support with your booking reference.'
    );
  }
  try {
    const raw = req.query.data || req.body?.data;
    if (!raw) {
      console.warn('Hesabe success callback called with no data param');
      return res.redirect(302, `${FRONTEND}?payment-failed=1&reason=no_data`);
    }
    const decrypted = hesabeCrypt.decrypt(decodeURIComponent(raw));
    const { resultCode, amount, paymentId, paymentToken, orderReferenceNumber, variable1, method } = decrypted;
    bookingRef      = variable1 || orderReferenceNumber;
    const isSuccess = ['CAPTURED', 'ACCEPT', 'SUCCESS'].includes(resultCode);
    console.log(` Hesabe success callback: ref=${bookingRef} code=${resultCode} amount=${amount}`);
    // Log to DB (don't throw if this fails)
    await db.query(
      `INSERT INTO payment_webhook_log
         (booking_ref, raw_payload, decrypted_data, result_code, payment_id, amount, processed)
       VALUES ($1,$2,$3::JSONB,$4,$5,$6,$7)`,
      [bookingRef, raw, JSON.stringify(decrypted), resultCode, paymentId, amount, isSuccess]
    ).catch(e => console.error('Log failed:', e.message));
    if (isSuccess) {
      await confirmPayment(bookingRef, paymentId, paymentToken, resultCode, method, amount);
      const successUrl = `${FRONTEND}?booking-confirmed=1&ref=${encodeURIComponent(bookingRef)}&paid=${amount}&method=${method || ''}`;
      console.log(` Payment confirmed, redirecting to: ${successUrl}`);
      return res.redirect(302, successUrl);
    } else {
      await db.query(
        `UPDATE bookings SET payment_status='FAILED', updated_at=NOW() WHERE booking_ref=$1`,
        [bookingRef]
      ).catch(() => {});
      const failUrl = `${FRONTEND}?payment-failed=1&ref=${encodeURIComponent(bookingRef)}&reason=${resultCode}`;
      return res.redirect(302, failUrl);
    }
  } catch (err) {
    console.error('Hesabe success callback error:', err.message);
    const failUrl = bookingRef
      ? `${FRONTEND}?payment-failed=1&ref=${encodeURIComponent(bookingRef)}`
      : `${FRONTEND}?payment-failed=1`;
    return res.redirect(302, failUrl);
  }
}
app.get('/api/payments/hesabe/success',  handleHesabeSuccess);
app.post('/api/payments/hesabe/success', handleHesabeSuccess);
// Step 3: Failure callback
// Hesabe may call this as GET or POST — handle both
// URL: /api/payments/hesabe/failure?data=ENCRYPTED
async function handleHesabeFailure(req, res) {
  const FRONTEND = (process.env.FRONTEND_URL || '').replace(/\/$/, '');
  let bookingRef = null;
  // Safety: if FRONTEND_URL is not set, log clearly
  if (!FRONTEND) {
    console.error(' FRONTEND_URL is not set — cannot redirect passenger after failure');
    return res.status(500).send(
      'Payment gateway callback error: FRONTEND_URL not configured on server. ' +
      'Please contact support. Your payment was NOT charged.'
    );
  }
  try {
    // data may arrive in query string (GET) or request body (POST)
    const raw = req.query.data || req.body?.data;
    if (raw) {
      const decrypted = hesabeCrypt.decrypt(decodeURIComponent(raw));
      bookingRef = decrypted.variable1 || decrypted.orderReferenceNumber;
      console.log(` Hesabe failure: ref=${bookingRef} code=${decrypted.resultCode}`);
      // Log to DB
      await db.query(
        `INSERT INTO payment_webhook_log
           (booking_ref, raw_payload, decrypted_data, result_code, processed)
         VALUES ($1,$2,$3::JSONB,$4,FALSE)
         ON CONFLICT DO NOTHING`,
        [bookingRef, raw, JSON.stringify(decrypted), decrypted.resultCode || 'FAILED']
      ).catch(() => {}); // don't throw if log fails
      if (bookingRef) {
        await db.query(
          `UPDATE bookings
           SET payment_status = 'FAILED', updated_at = NOW()
           WHERE booking_ref = $1 AND payment_status = 'PENDING'`,
          [bookingRef]
        ).catch(() => {});
      }
    }
  } catch (err) {
    console.error('Failure callback decrypt error:', err.message);
  }
  // Redirect passenger back to frontend failure page
  const redirectTo = bookingRef
    ? `${FRONTEND}?payment-failed=1&ref=${encodeURIComponent(bookingRef)}`
    : `${FRONTEND}?payment-failed=1`;
  console.log(`  Redirecting to: ${redirectTo}`);
  return res.redirect(302, redirectTo);
}
app.get('/api/payments/hesabe/failure',  handleHesabeFailure);
app.post('/api/payments/hesabe/failure', handleHesabeFailure);
// Step 4: Webhook — server-to-server from Hesabe (most reliable)
// POST /api/payments/hesabe/webhook
app.post('/api/payments/hesabe/webhook', async (req, res) => {
  let bookingRef = null;
  try {
    const body    = typeof req.body === 'string' ? req.body : JSON.stringify(req.body);
    const parsed  = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
    const { data } = parsed;
    if (!data) return res.status(400).json({ error: 'No data in webhook' });
    const decrypted = hesabeCrypt.decrypt(data);
    const {
      resultCode,
      amount,
      paymentId,
      paymentToken,
      paidOn,
      orderReferenceNumber,
      variable1,
      method,
    } = decrypted;
    bookingRef        = variable1 || orderReferenceNumber;
    const isSuccess   = ['CAPTURED', 'ACCEPT', 'SUCCESS'].includes(resultCode);
    console.log(`
    // Log raw
 Hesabe Webhook: ${resultCode} | ${bookingRef} | KWD ${amount}`);
    await db.query(
      `INSERT INTO payment_webhook_log
         (booking_ref, raw_payload, decrypted_data, result_code, payment_id, amount, processed)
       VALUES ($1,$2,$3::JSONB,$4,$5,$6,$7)`,
      [bookingRef, body, JSON.stringify(decrypted), resultCode, paymentId, amount, isSuccess]
    );
    if (isSuccess) {
      // Idempotency — skip if already processed
      const existing = await db.query(
        `SELECT payment_status FROM bookings WHERE booking_ref = $1`,
        [bookingRef]
      );
      if (existing.rows[0]?.payment_status === 'PAID') {
        console.log(` Webhook: ${bookingRef} already paid, skipping`);
        return res.json({ status: 'already_processed' });
      }
      await confirmPayment(bookingRef, paymentId, paymentToken, resultCode, method, amount);
    } else {
      await db.query(
        `UPDATE bookings SET payment_status='FAILED', updated_at=NOW() WHERE booking_ref=$1`,
        [bookingRef]
      );
    }
    res.json({ status: 'ok' });
  } catch (err) {
    console.error('Webhook processing error:', err.message);
    res.status(500).json({ error: 'Webhook processing failed' });
  }
});
// ─── Shared: Confirm payment + mark seats + send notifications ──
async function confirmPayment(bookingRef, paymentId, paymentToken, resultCode, method, amount) {
  const client = await db.connect();
  try {
    await client.query('BEGIN');
    const bookingResult = await client.query(
      `UPDATE bookings
       SET payment_status      = 'PAID',
           hesabe_payment_id   = $1,
           hesabe_payment_token= $2,
           hesabe_result_code  = $3,
           hesabe_method       = $4,
           paid_at             = NOW(),
           updated_at          = NOW()
       WHERE booking_ref = $5 AND payment_status != 'PAID'
       RETURNING id`,
      [paymentId, paymentToken, resultCode, method || null, bookingRef]
    );
    if (!bookingResult.rows.length) {
      await client.query('ROLLBACK');
      return; // Already processed
    }
    const bookingId = bookingResult.rows[0].id;
    // Mark seats as BOOKED
    await client.query(
      `UPDATE seats
       SET status = 'BOOKED', locked_until = NULL, locked_by = NULL, updated_at = NOW()
       WHERE id IN (SELECT seat_id FROM passengers WHERE booking_id = $1)`,
      [bookingId]
    );
    await client.query('COMMIT');
    console.log(` Payment confirmed: ${bookingRef} — KWD ${amount} via method ${method}`);
    // Send notifications (async, don't wait)
    sendTicketNotifications(bookingId).catch(err =>
      console.error('Post-payment notification error:', err.message)
    );
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('confirmPayment error:', err.message);
    throw err;
  } finally {
    client.release();
  }
}
// Check payment status by booking ref
// GET /api/payments/status/:ref
app.get('/api/payments/status/:ref', async (req, res) => {
  try {
    const result = await db.query(
      `SELECT booking_ref, payment_status, hesabe_payment_id, hesabe_method,
              total_amount, currency, paid_at
       FROM bookings WHERE booking_ref = $1`,
      [req.params.ref.toUpperCase()]
    );
    if (!result.rows.length) return sendError(res, 404, 'Booking not found');
    res.json({ success: true, ...result.rows[0] });
  } catch (err) {
    sendError(res, 500, 'Status check failed', err.message);
  }
});
// ============================================================
// ─── ROUTES: ADMIN (require admin JWT) ───────────────────────
// ============================================================
// ── Operators ─────────────────────────────────────────────────
app.get('/api/admin/operators', requireAdmin, async (_req, res) => {
  const result = await db.query('SELECT * FROM operators ORDER BY name');
  res.json({ success: true, operators: result.rows });
});
app.post('/api/admin/operators', requireAdmin, async (req, res) => {
  try {
    const { name, trade_name, phone, email, country = 'KW', currency = 'KWD' } = req.body;
    if (!name) return sendError(res, 400, 'name is required');
    const result = await db.query(
      `INSERT INTO operators (name, trade_name, phone, email, country, currency)
       VALUES ($1,$2,$3,$4,$5,$6) RETURNING *`,
      [name, trade_name, phone, email, country, currency]
    );
    res.status(201).json({ success: true, operator: result.rows[0] });
  } catch (err) { sendError(res, 500, 'Could not create operator', err.message); }
});
// ── Buses ──────────────────────────────────────────────────────
app.get('/api/admin/buses', requireAdmin, async (req, res) => {
  const { operator_id } = req.query;
  const filter   = operator_id ? 'WHERE operator_id = $1' : '';
  const params   = operator_id ? [operator_id] : [];
  const result   = await db.query(`SELECT * FROM buses ${filter} ORDER BY operator_name`, params);
  res.json({ success: true, buses: result.rows });
});
app.post('/api/admin/buses', requireAdmin, async (req, res) => {
  try {
    const { operator_id, operator_name, registration_no, bus_type, total_seats, amenities, seat_layout } = req.body;
    if (!operator_id || !operator_name || !total_seats)
      return sendError(res, 400, 'operator_id, operator_name, total_seats required');
    const result = await db.query(
      `INSERT INTO buses
         (operator_id, operator_name, registration_no, bus_type, total_seats, amenities, seat_layout)
       VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *`,
      [operator_id, operator_name, registration_no, bus_type || 'AC_SEATER',
       total_seats, amenities || [], seat_layout ? JSON.stringify(seat_layout) : null]
    );
    res.status(201).json({ success: true, bus: result.rows[0] });
  } catch (err) { sendError(res, 500, 'Could not create bus', err.message); }
});
// ── Routes ─────────────────────────────────────────────────────
app.get('/api/admin/routes', requireAdmin, async (_req, res) => {
  const result = await db.query('SELECT * FROM routes ORDER BY origin_city, destination_city');
  res.json({ success: true, routes: result.rows });
});
app.post('/api/admin/routes', requireAdmin, async (req, res) => {
  try {
    const { origin_city, destination_city, distance_km, estimated_hours, stops } = req.body;
    if (!origin_city || !destination_city)
      return sendError(res, 400, 'origin_city and destination_city required');
    const result = await db.query(
      `INSERT INTO routes (origin_city, destination_city, distance_km, estimated_hours, stops)
       VALUES ($1,$2,$3,$4,$5) RETURNING *`,
      [origin_city, destination_city, distance_km || null, estimated_hours || null,
       stops ? JSON.stringify(stops) : '[]']
    );
    res.status(201).json({ success: true, route: result.rows[0] });
  } catch (err) { sendError(res, 500, 'Could not create route', err.message); }
});
// ── Schedules ──────────────────────────────────────────────────
app.get('/api/admin/schedules', requireAdmin, async (req, res) => {
  try {
    const result = await db.query(
      `SELECT s.*, b.operator_name, b.bus_type, r.origin_city, r.destination_city,
              COUNT(st.id) FILTER (WHERE st.status='AVAILABLE') AS available_seats,
              COUNT(st.id) AS total_seats
       FROM schedules s
       JOIN buses b  ON s.bus_id   = b.id
       JOIN routes r ON s.route_id = r.id
       LEFT JOIN seats st ON st.schedule_id = s.id
       GROUP BY s.id, b.operator_name, b.bus_type, r.origin_city, r.destination_city
       ORDER BY s.departure_time DESC
       LIMIT 100`
    );
    res.json({ success: true, schedules: result.rows });
  } catch (err) { sendError(res, 500, 'Could not fetch schedules', err.message); }
});
// Create schedule + auto-generate seat rows
app.post('/api/admin/schedules', requireAdmin, async (req, res) => {
  const {
    bus_id, route_id, departure_time, arrival_time,
    base_fare, currency = 'KWD', pickup_points, drop_points,
  } = req.body;
  if (!bus_id || !route_id || !departure_time || !arrival_time || !base_fare)
    return sendError(res, 400, 'bus_id, route_id, departure_time, arrival_time, base_fare required');
  const client = await db.connect();
  try {
    await client.query('BEGIN');
    const schedResult = await client.query(
      `INSERT INTO schedules
         (bus_id, route_id, departure_time, arrival_time, base_fare,
          currency, pickup_points, drop_points)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *`,
      [bus_id, route_id, departure_time, arrival_time, formatKWD(base_fare), currency,
       pickup_points ? JSON.stringify(pickup_points) : '[]',
       drop_points   ? JSON.stringify(drop_points)   : '[]']
    );
    const schedule = schedResult.rows[0];
    // Fetch bus seat count and layout
    const busResult = await client.query(
      'SELECT total_seats, seat_layout FROM buses WHERE id = $1', [bus_id]
    );
    const { total_seats, seat_layout } = busResult.rows[0];
    const ladiesSeats = seat_layout?.ladies_seats || [];
    // Auto-create seat rows
    for (let i = 1; i <= total_seats; i++) {
      const sNum  = String(i);
      const sType = ladiesSeats.includes(sNum)  ? 'LADIES_ONLY'
                  : i % 4 === 1 || i % 4 === 3  ? 'WINDOW'
                  : 'AISLE';
      await client.query(
        `INSERT INTO seats (schedule_id, seat_number, seat_type, price) VALUES ($1,$2,$3,$4)`,
        [schedule.id, sNum, sType, formatKWD(base_fare)]
      );
    }
    await client.query('COMMIT');
    res.status(201).json({ success: true, schedule, seats_created: total_seats });
  } catch (err) {
    await client.query('ROLLBACK');
    sendError(res, 500, 'Could not create schedule', err.message);
  } finally {
    client.release();
  }
});
// Update schedule status (delay, cancel)
app.patch('/api/admin/schedules/:id', requireAdmin, async (req, res) => {
  try {
    const { status, delay_minutes, new_departure_time, cancellation_reason, alert_message } = req.body;
    const allowedStatuses = ['SCHEDULED','DELAYED','CANCELLED','DEPARTED','COMPLETED'];
    if (status && !allowedStatuses.includes(status))
      return sendError(res, 400, `Invalid status. Use: ${allowedStatuses.join(', ')}`);
    await db.query(
      `UPDATE schedules
       SET status               = COALESCE($1, status),
           delay_minutes        = COALESCE($2, delay_minutes),
           departure_time       = COALESCE($3::TIMESTAMPTZ, departure_time),
           cancellation_reason  = COALESCE($4, cancellation_reason),
           updated_at           = NOW()
       WHERE id = $5`,
      [status, delay_minutes, new_departure_time, cancellation_reason, req.params.id]
    );
    // Send passenger alert if message provided
    let alertResult = null;
    if (alert_message) {
      const alertType = status === 'CANCELLED' ? 'CANCELLATION'
                      : status === 'DELAYED'   ? 'DELAY'
                      : 'SCHEDULE_CHANGE';
      alertResult = await sendTripAlert(req.params.id, alertType, alert_message, req.user?.id);
    }
    res.json({ success: true, alert: alertResult });
  } catch (err) { sendError(res, 500, 'Could not update schedule', err.message); }
});
// ── Notify passengers on a trip ────────────────────────────────
// POST /api/admin/notify
app.post('/api/admin/notify', requireAdmin, async (req, res) => {
  try {
    const { schedule_id, alert_type, message } = req.body;
    if (!schedule_id || !alert_type || !message)
      return sendError(res, 400, 'schedule_id, alert_type, message required');
    const validTypes = ['SCHEDULE_CHANGE','PICKUP_CHANGE','CANCELLATION','DELAY','REMINDER','GENERAL'];
    if (!validTypes.includes(alert_type))
      return sendError(res, 400, `Invalid alert_type. Use: ${validTypes.join(', ')}`);
    const result = await sendTripAlert(schedule_id, alert_type, message, req.user?.id);
    res.json({ success: true, ...result });
  } catch (err) { sendError(res, 500, 'Could not send alerts', err.message); }
});
// ── Booking management ─────────────────────────────────────────
app.get('/api/admin/bookings', requireAdmin, async (req, res) => {
  try {
    const { status, schedule_id, from, to, page = 1, limit = 50 } = req.query;
    const offset = (parseInt(page) - 1) * parseInt(limit);
    let query  = `SELECT * FROM v_booking_details WHERE 1=1`;
    const vals = [];
    let idx    = 1;
    if (status)      { query += ` AND payment_status = $${idx++}`;    vals.push(status); }
    if (schedule_id) { query += ` AND schedule_id    = $${idx++}`;    vals.push(schedule_id); }
    if (from)        { query += ` AND departure_time >= $${idx++}::TIMESTAMPTZ`; vals.push(from); }
    if (to)          { query += ` AND departure_time <= $${idx++}::TIMESTAMPTZ`; vals.push(to); }
    query += ` ORDER BY created_at DESC LIMIT $${idx++} OFFSET $${idx++}`;
    vals.push(parseInt(limit), offset);
    const result = await db.query(query, vals);
    res.json({ success: true, bookings: result.rows, page: parseInt(page) });
  } catch (err) { sendError(res, 500, 'Could not fetch bookings', err.message); }
});
// Cancel booking and release seats
app.post('/api/admin/bookings/:ref/cancel', requireAdmin, async (req, res) => {
  const client = await db.connect();
  try {
    await client.query('BEGIN');
    const result = await client.query(
      `UPDATE bookings
       SET payment_status = 'REFUNDED', cancelled_at = NOW(),
           cancellation_reason = $1, updated_at = NOW()
       WHERE booking_ref = $2 AND payment_status IN ('PAID','PENDING')
       RETURNING id`,
      [req.body.reason || 'Admin cancellation', req.params.ref.toUpperCase()]
    );
    if (!result.rows.length) throw new Error('Booking not found or already cancelled');
    await client.query(
      `UPDATE seats SET status='AVAILABLE', locked_until=NULL, locked_by=NULL
       WHERE id IN (SELECT seat_id FROM passengers WHERE booking_id=$1)`,
      [result.rows[0].id]
    );
    await client.query('COMMIT');
    res.json({ success: true, message: 'Booking cancelled and seats released' });
  } catch (err) {
    await client.query('ROLLBACK');
    sendError(res, 400, err.message);
  } finally { client.release(); }
});
// ── Revenue reports ────────────────────────────────────────────
app.get('/api/admin/reports/revenue', requireAdmin, async (req, res) => {
  try {
    const { from, to, group_by = 'day' } = req.query;
    const fromDate = from || new Date(Date.now() - 30 * 86400000).toISOString();
    const toDate   = to   || new Date().toISOString();
    const trunc = group_by === 'month' ? 'month' : group_by === 'week' ? 'week' : 'day';
    const result = await db.query(
      `SELECT
         DATE_TRUNC($1, paid_at AT TIME ZONE 'Asia/Kuwait') AS period,
         COUNT(*) FILTER (WHERE payment_status='PAID')       AS bookings,
         SUM(total_amount) FILTER (WHERE payment_status='PAID') AS revenue,
         AVG(total_amount) FILTER (WHERE payment_status='PAID') AS avg_ticket,
         COUNT(*) FILTER (WHERE hesabe_method=1)             AS knet_count,
         COUNT(*) FILTER (WHERE hesabe_method=2)             AS card_count,
         COUNT(*) FILTER (WHERE hesabe_method=10)            AS applepay_count
       FROM bookings
       WHERE created_at BETWEEN $2 AND $3
       GROUP BY period
       ORDER BY period DESC`,
      [trunc, fromDate, toDate]
    );
    res.json({ success: true, from: fromDate, to: toDate, data: result.rows });
  } catch (err) { sendError(res, 500, 'Report failed', err.message); }
});
// ── Admin user management ──────────────────────────────────────
app.post('/api/admin/users', requireAdmin, async (req, res) => {
  try {
    if (req.user.role !== 'SUPER_ADMIN')
      return sendError(res, 403, 'Only SUPER_ADMIN can create users');
    const { email, password, full_name, role = 'ADMIN', operator_id } = req.body;
    if (!email || !password) return sendError(res, 400, 'email and password required');
    const hash   = await bcrypt.hash(password, 12);
    const result = await db.query(
      `INSERT INTO admin_users (email, password_hash, full_name, role, operator_id)
       VALUES ($1,$2,$3,$4,$5) RETURNING id, email, full_name, role`,
      [email.toLowerCase(), hash, full_name, role, operator_id || null]
    );
    res.status(201).json({ success: true, user: result.rows[0] });
  } catch (err) {
    sendError(res, 500, err.message.includes('unique') ? 'Email already exists' : err.message);
  }
});
// ── Promo codes ────────────────────────────────────────────────
app.get('/api/admin/promos', requireAdmin, async (_req, res) => {
  const result = await db.query('SELECT * FROM promo_codes ORDER BY created_at DESC');
  res.json({ success: true, promos: result.rows });
});
app.post('/api/admin/promos', requireAdmin, async (req, res) => {
  try {
    const { code, description, discount_type, discount_value, max_uses, valid_until, min_order_amount } = req.body;
    if (!code || !discount_value) return sendError(res, 400, 'code and discount_value required');
    const result = await db.query(
      `INSERT INTO promo_codes
         (code, description, discount_type, discount_value, max_uses, valid_until, min_order_amount)
       VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *`,
      [code.toUpperCase(), description, discount_type || 'PERCENT',
       discount_value, max_uses || null, valid_until || null, min_order_amount || 0]
    );
    res.status(201).json({ success: true, promo: result.rows[0] });
  } catch (err) {
    sendError(res, 500, err.message.includes('unique') ? 'Promo code already exists' : err.message);
  }
});
// Validate a promo code (called from frontend checkout)
app.post('/api/promos/validate', async (req, res) => {
  try {
    const { code, amount } = req.body;
    if (!code) return sendError(res, 400, 'code required');
    const result = await db.query(
      `SELECT * FROM promo_codes
       WHERE code = $1 AND is_active = TRUE
         AND (valid_until IS NULL OR valid_until > NOW())
         AND (max_uses IS NULL OR uses_count < max_uses)`,
      [code.toUpperCase().trim()]
    );
    if (!result.rows.length) return res.json({ success: false, error: 'Invalid or expired promo code' });
    const promo = result.rows[0];
    if (amount && parseFloat(amount) < parseFloat(promo.min_order_amount)) {
      return res.json({ success: false, error: `Minimum order amount is KWD ${promo.min_order_amount}` });
    }
    const discount = promo.discount_type === 'PERCENT'
      ? (parseFloat(amount) * promo.discount_value / 100).toFixed(3)
      : promo.discount_value.toFixed(3);
    res.json({ success: true, promo: { code: promo.code, discount_type: promo.discount_type, discount_value: promo.discount_value, discount_amount: discount } });
  } catch (err) { sendError(res, 500, 'Could not validate promo', err.message); }
});
// ============================================================
// ─── GLOBAL ERROR HANDLER ────────────────────────────────────
// ============================================================
app.use((err, _req, res, _next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ success: false, error: 'Internal server error' });
});
// 404 handler
app.use((_req, res) => {
  res.status(404).json({ success: false, error: 'Route not found' });
});
// ============================================================
// ─── START SERVER ────────────────────────────────────────────
// ============================================================
app.listen(PORT, () => {
  console.log(`\n RouteRide API running on port ${PORT}`);
  console.log(`   Mode:     ${process.env.NODE_ENV || 'development'}`);
  console.log(`   Hesabe:   ${HESABE_IS_PROD ? ' PRODUCTION' : ' SANDBOX'}`);
  console.log(`   DB:       ${process.env.DATABASE_URL?.split('@')[1] || 'connected'}`);
  console.log(`   Frontend: ${process.env.FRONTEND_URL || 'not set'}\n`);
});
module.exports = app;