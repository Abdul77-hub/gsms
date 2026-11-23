const express = require('express'), mongoose = require('mongoose'), bcrypt = require('bcryptjs'),
  jwt = require('jsonwebtoken'), ExcelJS = require('exceljs'), PDF = require('pdfkit'), path = require('path');
const { MONGO_URI = 'mongodb://127.0.0.1:27017/gsms', JWT_SECRET = 'change-me-in-production', PORT = 3000 } = process.env;
if (process.env.NODE_ENV === 'production' && JWT_SECRET === 'change-me-in-production') { console.error('Set JWT_SECRET'); process.exit(1); }

const app = express();
if (process.env.TRUST_PROXY) app.set('trust proxy', 1);
app.disable('x-powered-by');
app.use((q, s, n) => {
  s.set({ 'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY', 'Referrer-Policy': 'no-referrer',
    'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'" });
  if (process.env.NODE_ENV === 'production') s.set('Strict-Transport-Security', 'max-age=31536000');
  n();
});
app.use(express.json({ limit: '100kb' }));
app.use(express.static(path.join(__dirname, 'public')));

const mk = (n, o) => mongoose.model(n, new mongoose.Schema(o, { versionKey: false }));
const User = mk('User', { email: { type: String, unique: true }, hash: String, role: String, name: String, ward: String, active: { type: Boolean, default: true } });
const Sem = mk('Seminar', { id: { type: Number, unique: true }, t: String, m: String, ref: String, v: String, dt: String, dl: String, cap: Number, base: Number, q: Number, st: String });
const Del = mk('Delegate', { id: { type: String, unique: true }, name: String, age: Number, sex: String, job: String, ph: String, ward: String, dist: String, sem: Number, by: String, byUser: String, st: String, why: String, date: String });

const WARDS = { 'Hodan Ward 3': 'Hodan', 'Waberi Central': 'Waberi', 'Hawl Wadag': 'Hawl Wadag', 'Bondhere': 'Bondhere' };
const PH = /^\+252\d{9}$/, H = { _id: 0 };
const wrap = f => (q, s) => f(q, s).catch(e => { console.error(e); if (!s.headersSent) s.status(500).json({ error: 'Server error' }); });
const bad = (s, m) => s.status(400).json({ error: m });

// Auth: JWT bearer token; role/ward/active are re-read from the DB on every request (disabled users lose access immediately)
const auth = (...roles) => async (q, s, next) => {
  try {
    const p = jwt.verify((q.headers.authorization || '').replace('Bearer ', ''), JWT_SECRET);
    const u = await User.findOne({ email: p.email }, { role: 1, ward: 1, name: 1, active: 1, _id: 0 }).lean();
    if (!u || u.active === false) return s.status(401).json({ error: 'Unauthorized' });
    q.u = { email: p.email, role: u.role, ward: u.ward, name: u.name };
  } catch (_) { return s.status(401).json({ error: 'Unauthorized' }); }
  if (roles.length && !roles.includes(q.u.role)) return s.status(403).json({ error: 'Forbidden' });
  next();
};
// Row-level scope: admin sees all, chair sees own ward, submitter sees own nominations
const scope = u => u.role === 'admin' ? {} : u.role === 'chair' ? { ward: u.ward } : { byUser: u.email };

const fails = new Map(); // login throttle: 5 failures / 15 min per IP+email
setInterval(() => fails.clear(), 3600e3).unref();
const blocked = k => { const now = Date.now(), a = (fails.get(k) || []).filter(t => now - t < 15 * 60e3); fails.set(k, a); return a.length >= 5; };
app.post('/api/login', wrap(async (q, s) => {
  const { email = '', password = '', role } = q.body, em = String(email).toLowerCase().trim(), key = q.ip + '|' + em;
  if (blocked(key)) return s.status(429).json({ error: 'Too many attempts. Try again in 15 minutes.' });
  const u = await User.findOne({ email: em });
  if (!u || u.active === false || (role && u.role !== role) || !bcrypt.compareSync(String(password), u.hash)) { fails.get(key).push(Date.now()); return s.status(401).json({ error: 'Invalid credentials' }); }
  fails.delete(key);
  const token = jwt.sign({ email: u.email }, JWT_SECRET, { expiresIn: '12h' });
  s.json({ token, role: u.role, name: u.name, ward: u.ward });
}));

app.get('/api/data', auth(), wrap(async (q, s) => {
  const sc = scope(q.u), del = await Del.find(sc, H).sort({ id: 1 }).lean(), sem = await Sem.find({}, H).sort({ id: 1 }).lean();
  if (q.u.role !== 'admin') { // keep seat counts global even though delegates are scoped
    const out = await Del.find({ $nor: [sc], st: { $ne: 'rejected' } }, { sem: 1, _id: 0 }).lean();
    sem.forEach(x => x.base += out.filter(d => d.sem === x.id).length);
  }
  s.json({ del, sem });
}));

app.patch('/api/delegates/:id', auth('admin', 'chair'), wrap(async (q, s) => {
  const { st, why = '' } = q.body, d = await Del.findOne({ id: q.params.id });
  if (!d) return s.status(404).json({ error: 'Not found' });
  const ok = q.u.role === 'admin' ? ['approved', 'rejected', 'pending'].includes(st)
    : d.ward === q.u.ward && d.st === 'ward' && ['pending', 'rejected'].includes(st);
  if (!ok) return s.status(403).json({ error: 'Not allowed' });
  d.st = st; d.why = st === 'rejected' ? String(why).slice(0, 300) : '';
  await d.save(); s.json({ ok: true });
}));

app.post('/api/delegates/batch', auth('admin'), wrap(async (q, s) => {
  const ids = [].concat(q.body.ids || []).map(String);
  const r = await Del.updateMany({ id: { $in: ids }, st: { $in: ['pending', 'ward'] } }, { st: 'approved', why: '' });
  s.json({ n: r.modifiedCount });
}));

app.post('/api/delegates', auth(), wrap(async (q, s) => {
  const b = q.body, u = q.u, name = String(b.name || '').trim().replace(/\s+/g, ' '), ph = String(b.ph || '').replace(/\s/g, '');
  const ward = u.role === 'chair' ? u.ward : b.ward, age = +b.age, sem = await Sem.findOne({ id: +b.sem });
  if (name.split(' ').length < 3) return bad(s, 'Candidate needs a full 3-part legal name');
  if (!PH.test(ph)) return bad(s, 'Invalid Mogadishu phone number');
  if (!(age >= 18 && age <= 90)) return bad(s, 'Candidate must be 18 or older');
  if (!WARDS[ward]) return bad(s, 'Unknown ward');
  if (!sem || sem.st !== 'open') return bad(s, 'Seminar is not open');
  const esc = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  if (await Del.exists({ st: { $ne: 'rejected' }, $or: [{ ph }, { name: new RegExp('^' + esc + '$', 'i') }] })) return bad(s, 'Duplicate detected in the national registry');
  const act = await Del.find({ sem: sem.id, st: { $ne: 'rejected' } }, { ward: 1, _id: 0 }).lean();
  if (sem.base + act.length >= sem.cap || act.filter(d => d.ward === ward).length >= sem.q) return bad(s, 'Quota exceeded for this ward or seminar');
  const id = 'SOM-' + (9001 + await Del.countDocuments());
  await Del.create({ id, name, age, sex: b.sex === 'M' ? 'M' : 'F', job: String(b.job || '').slice(0, 80), ph, ward, dist: WARDS[ward], sem: sem.id,
    by: u.name, byUser: u.email, st: u.role === 'admin' ? 'pending' : 'ward', why: '',
    date: new Date().toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' }) });
  s.json({ ok: true, id });
}));

app.post('/api/seminars', auth('admin'), wrap(async (q, s) => {
  const b = q.body, last = await Sem.findOne().sort({ id: -1 }), id = last ? last.id + 1 : 1;
  if (!String(b.t || '').trim() || !(+b.cap > 0)) return bad(s, 'Title and total seats are required');
  await Sem.create({ id, t: String(b.t).trim(), m: b.m || 'Ministry TBD', ref: 'GSMS-' + new Date().getFullYear() + '-NEW-' + id, v: b.v || 'TBD', dt: b.dt || 'TBD', dl: b.dl || 'TBD', cap: +b.cap, base: 0, q: +b.q || 10, st: 'draft' });
  s.json({ ok: true, id });
}));
app.post('/api/seminars/:id/publish', auth('admin'), wrap(async (q, s) => { await Sem.updateOne({ id: +q.params.id }, { st: 'open' }); s.json({ ok: true }); }));

app.put('/api/seminars/:id', auth('admin'), wrap(async (q, s) => {
  const b = q.body, x = await Sem.findOne({ id: +q.params.id });
  if (!x) return s.status(404).json({ error: 'Not found' });
  if (!String(b.t || '').trim() || !(+b.cap > 0) || !(+b.q > 0)) return bad(s, 'Title, total seats and seats per ward are required');
  const filled = x.base + await Del.countDocuments({ sem: x.id, st: { $ne: 'rejected' } });
  if (+b.cap < filled) return bad(s, 'Total seats cannot be below seats already filled (' + filled + ')');
  const t = v => String(v || '').trim().slice(0, 200);
  Object.assign(x, { t: t(b.t), m: t(b.m) || x.m, v: t(b.v) || x.v, dt: t(b.dt) || x.dt, dl: t(b.dl) || x.dl, cap: +b.cap, q: +b.q });
  await x.save(); s.json({ ok: true });
}));

// User management (admin only)
app.get('/api/users', auth('admin'), wrap(async (q, s) => s.json(await User.find({}, { _id: 0, hash: 0 }).sort({ email: 1 }).lean())));
app.post('/api/users', auth('admin'), wrap(async (q, s) => {
  const b = q.body, email = String(b.email || '').toLowerCase().trim(), name = String(b.name || '').trim().slice(0, 100);
  if (!/^\S+@\S+\.\S+$/.test(email) || !name) return bad(s, 'Valid name and email are required');
  if (!['admin', 'chair', 'sub'].includes(b.role)) return bad(s, 'Invalid role');
  if (b.role === 'chair' && !WARDS[b.ward]) return bad(s, 'Chairperson needs a ward');
  if (typeof b.password !== 'string' || b.password.length < 10) return bad(s, 'Password must be at least 10 characters');
  if (await User.exists({ email })) return bad(s, 'Email already exists');
  await User.create({ email, name, role: b.role, ward: b.role === 'chair' ? b.ward : undefined, hash: bcrypt.hashSync(b.password, 10), active: true });
  s.json({ ok: true });
}));
app.post('/api/users/toggle', auth('admin'), wrap(async (q, s) => {
  const email = String(q.body.email || '').toLowerCase();
  if (email === q.u.email) return bad(s, 'You cannot disable your own account');
  const u = await User.findOne({ email });
  if (!u) return s.status(404).json({ error: 'Not found' });
  u.active = u.active === false; await u.save(); s.json({ ok: true });
}));
app.post('/api/users/password', auth('admin'), wrap(async (q, s) => {
  const u = await User.findOne({ email: String(q.body.email || '').toLowerCase() }), p = q.body.password;
  if (!u) return s.status(404).json({ error: 'Not found' });
  if (typeof p !== 'string' || p.length < 10) return bad(s, 'Password must be at least 10 characters');
  u.hash = bcrypt.hashSync(p, 10); await u.save(); s.json({ ok: true });
}));

// Export: /api/export?format=xlsx|csv|pdf&f=all|pending|approved|rejected&sm=<seminarId>&q=<text>  (respects the caller's scope)
app.get('/api/export', auth(), wrap(async (q, s) => {
  const { format = 'xlsx', f = 'all', sm = 'all', q: qq = '' } = q.query, Q = String(qq).toLowerCase();
  let rows = await Del.find(scope(q.u), H).sort({ id: 1 }).lean();
  rows = rows.filter(d => (f === 'all' || (f === 'pending' ? ['pending', 'ward'].includes(d.st) : d.st === f)) && (sm === 'all' || d.sem === +sm) && (!Q || (d.name + d.ph + d.id).toLowerCase().includes(Q)));
  const sems = Object.fromEntries((await Sem.find({}, H).lean()).map(x => [x.id, x.t]));
  const safe = v => /^[=+\-@]/.test(String(v)) ? "'" + v : v; // neutralise spreadsheet formula injection
  const cols = ['ID', 'Name', 'Phone', 'Ward', 'Seminar', 'Nominated by', 'Status', 'Date'];
  const data = rows.map(d => [d.id, safe(d.name), d.ph, d.ward, safe(sems[d.sem] || ''), safe(d.by), d.st, d.date]);
  if (format === 'csv') {
    const c = v => '"' + String(v).replace(/"/g, '""') + '"';
    s.type('text/csv').attachment('gsms-participants.csv').send('\ufeff' + [cols, ...data].map(r => r.map(c).join(',')).join('\r\n'));
  } else if (format === 'pdf') {
    const doc = new PDF({ margin: 30, size: 'A4', layout: 'landscape' });
    s.type('application/pdf').attachment('gsms-participants.pdf'); doc.pipe(s);
    doc.fontSize(14).text('GSMS Participants (' + rows.length + ')'); doc.moveDown().fontSize(8);
    data.forEach(r => doc.text([r[0], r[1], r[2], r[3], r[6], r[7]].join('  |  ')));
    doc.end();
  } else {
    const wb = new ExcelJS.Workbook(), ws = wb.addWorksheet('Participants');
    ws.addRow(cols).font = { bold: true }; data.forEach(r => ws.addRow(r)); ws.columns.forEach(c => c.width = 22);
    s.type('application/vnd.openxmlformats-officedocument.spreadsheetml.sheet').attachment('gsms-participants.xlsx');
    await wb.xlsx.write(s); s.end();
  }
}));

async function seed() {
  if (await User.countDocuments()) return;
  const h = p => bcrypt.hashSync(p, 10), pw = process.env.DEMO_PASSWORD || 'Gsms@2026';
  await User.insertMany([
    { email: 'admin.delegation@mofa.gov.so', hash: h(pw), role: 'admin', name: 'Ministry Registrar' },
    { email: 'ahmed.kheyre@hodan.gov.so', hash: h(pw), role: 'chair', name: 'Chairperson Ahmed Nur Kheyre', ward: 'Hodan Ward 3' },
    { email: 'halima.adan@community.so', hash: h(pw), role: 'sub', name: 'Halima Adan' }]);
  await Sem.insertMany([
    { id: 1, t: 'National Youth Leadership & Civic Ethics Seminar 2026', m: 'Ministry of Youth, Sports & Civic Engagement', ref: 'GSMS-2026-YTH-04', v: 'Mogadishu Central Conference Hall', dt: 'Dec 7–11, 2026', dl: 'Nov 30, 2026', cap: 100, base: 70, q: 20, st: 'open' },
    { id: 2, t: 'Public Finance Management & Transparency Workshop', m: 'Ministry of Finance & Planning', ref: 'GSMS-2026-FIN-09', v: 'National Institute of Administration, Hall A', dt: 'Dec 14–17, 2026', dl: 'Dec 7, 2026', cap: 60, base: 38, q: 15, st: 'open' },
    { id: 3, t: 'Municipal Climate Resilience & Disaster Preparedness', m: 'Ministry of Environment & Climate', ref: 'GSMS-2026-ENV-11', v: 'Banadir Regional Administrative Center', dt: 'Jan 11–16, 2027', dl: 'Jan 4, 2027', cap: 120, base: 0, q: 10, st: 'draft' }]);
  const W = Object.entries(WARDS), E = 'halima.adan@community.so';
  const D = [['Farhiya Ali Osman', 26, 'F', 'Civic Youth Leader', '+252615849201', 0, 1, 'Halima Adan (Community Elder)', 'ward', '', E], ['Guled Abdirahman Jama', 34, 'M', 'District Urban Planner', '+252615551018', 0, 2, 'Self-registered', 'ward'], ['Maryan Warsame Shire', 29, 'F', 'Local Finance Officer', '+252615552029', 0, 2, 'Omar Nur (Ward Coordinator)', 'ward'], ['Amina Yusuf Warsame', 31, 'F', 'Civil Servant', '+252615553030', 0, 1, 'Cpt. Daud (Chairman)', 'pending'], ['Liban Hassan Shire', 38, 'M', 'Health Officer', '+252615554041', 1, 2, 'Sahra Nur (Chairwoman)', 'pending'], ['Fadumo Abdi Farah', 27, 'F', 'Urban Engineer', '+252615555052', 2, 1, 'Ali Muse (Coordinator)', 'pending'], ['Mohamed Hassan Guled', 41, 'M', 'Budget Analyst', '+252615556063', 1, 2, 'Halima Omar (Chairperson)', 'approved'], ['Ibrahim Nuur Adan', 36, 'M', 'ICT Officer', '+252615557074', 3, 1, 'Dahir Gelle (Chairperson)', 'approved'], ['Fadumo Farah Ali', 33, 'F', 'Community Rep', '+252615558085', 2, 1, 'Community Rep Osman', 'rejected', 'Quota exceeded for ward'], ['Hodan Ahmed Ali', 25, 'F', 'Teacher', '+252615559096', 0, 1, 'Ahmed Nur Kheyre', 'approved']];
  await Del.insertMany(D.map((r, i) => ({ id: 'SOM-' + (9001 + i), name: r[0], age: r[1], sex: r[2], job: r[3], ph: r[4], ward: W[r[5]][0], dist: W[r[5]][1], sem: r[6], by: r[7], byUser: r[10] || '', st: r[8], why: r[9] || '', date: 'Nov ' + (10 + i) + ', 2026' })));
  console.log('Seeded demo data. Demo password:', pw);
}

mongoose.connect(MONGO_URI).then(seed).then(() => app.listen(PORT, () => console.log('GSMS running on http://localhost:' + PORT)))
  .catch(e => { console.error('Startup failed:', e.message); process.exit(1); });
