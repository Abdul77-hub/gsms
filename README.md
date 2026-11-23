# GSMS – Government Seminar Management System (backend + app)

Express + MongoDB + JWT. `public/index.html` is the full app (EN/Soomaali toggle); the server serves it and the REST API from the same origin.

## What is in this package
- `server.js`, `package.json`, `public/index.html` – the real app (backend + API + the same UI). Run it as described below.
- `demo/gsms-demo.html` – standalone demo of the same UI, no server needed: just open it in a browser (data is kept in that browser only, any login works).

## Run
1. Install Node.js 18+ and MongoDB (local, or an Atlas URI).
2. `npm install`
3. `JWT_SECRET="long-random-string" npm start`  (optional: `MONGO_URI`, `PORT`, `DEMO_PASSWORD`)
4. Open http://localhost:3000

First start seeds 3 users + demo seminars/delegates. Password for all demo users: `Gsms@2026` (or `DEMO_PASSWORD`).

| Role | Email |
|---|---|
| Super Admin | admin.delegation@mofa.gov.so |
| Chairperson (Hodan Ward 3) | ahmed.kheyre@hodan.gov.so |
| Submitter | halima.adan@community.so |

## What the server enforces
- Login (bcrypt + JWT, 12h). Role must match the chosen tier.
- Row-level scope: Admin sees all, Chairperson only their ward, Submitter only their own nominations.
- Chairperson can only endorse/return delegates of their own ward; only Admin approves/rejects, batch-approves, creates and publishes seminars.
- Nomination validation: 3-part name, +252 phone, age 18+, duplicate check, ward/seminar quota.
- Export (Excel/CSV/PDF) from the Participants screen, respecting role scope and active filters.

## Added in v2
- **Users** tab (Super Admin): create users, disable/enable, reset passwords. Disabled users lose access immediately (role/active are re-checked on every request).
- **Edit Details** on every seminar (seat total cannot go below seats already filled).
- Login throttle (5 failed attempts / 15 min per IP+email), security headers + CSP, HSTS in production. Behind a reverse proxy set `TRUST_PROXY=1` so the throttle sees real client IPs.

## Before real use
- Change/delete the demo users, set a strong `JWT_SECRET`, serve over HTTPS.
- 2-factor passcodes and the biometric / civil-registry checks shown in the designs are UI only, they are not implemented here.
- The throttle is in-memory (single instance). For several server instances use a shared store such as Redis.
