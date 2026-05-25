# Doctor Booked — Backend Integration Guide

## What you now have

```
backend/
├── src/
│   ├── index.js              ← Express server entry point
│   ├── db/
│   │   ├── init.js           ← Creates all SQLite tables
│   │   └── seed.js           ← Seeds the admin user
│   ├── middleware/
│   │   └── auth.js           ← JWT verification middleware
│   ├── routes/
│   │   ├── auth.js           ← Patient signup/login, doctor login, admin login
│   │   ├── hospitals.js      ← Full hospitals CRUD + photo upload
│   │   ├── doctors.js        ← Full doctors CRUD
│   │   ├── bookings.js       ← Booking creation, listing, stats
│   │   ├── tokens.js         ← Live token regulation, complete, skip, close
│   │   └── patients.js       ← Patient list (admin)
│   ├── services/
│   │   └── ws.js             ← WebSocket server for real-time token updates
│   └── utils/id.js
├── frontend-api-client/
│   ├── api.ts                ← Drop into src/frontend/src/api.ts
│   ├── StoreContext.tsx      ← Drop into src/frontend/src/context/StoreContext.tsx
│   ├── LoginPage.tsx         ← Drop into src/frontend/src/pages/LoginPage.tsx
│   └── .env.local.example   ← Copy to src/frontend/.env.local
├── .env.example              ← Copy to .env and edit
└── package.json
```

---

## Step 1 — Set up the backend

```bash
cd backend
npm install
cp .env.example .env
```

Open `.env` and change:
- `JWT_SECRET` to a long random string
- `ADMIN_PASSWORD` to something secure

```bash
# Initialise the database and create the admin user
node src/db/seed.js

# Start the backend server
npm run dev      # development (auto-restarts on file changes)
npm start        # production
```

You should see:
```
✅  Database initialised
🚀  Doctor Booked API running on http://localhost:4000
📡  WebSocket ready at ws://localhost:4000/ws?session=SESSION_ID
```

---

## Step 2 — Wire up the frontend

### 2a. Copy the API client files

```bash
# From the project root:
cp backend/frontend-api-client/api.ts              src/frontend/src/api.ts
cp backend/frontend-api-client/StoreContext.tsx    src/frontend/src/context/StoreContext.tsx
cp backend/frontend-api-client/LoginPage.tsx       src/frontend/src/pages/LoginPage.tsx
cp backend/frontend-api-client/.env.local.example src/frontend/.env.local
```

### 2b. Install the frontend (if not already done)

```bash
cd src/frontend
pnpm install
```

### 2c. Start the frontend dev server

```bash
cd src/frontend
pnpm dev
```

Open http://localhost:5173 — the app is now fully connected to the real backend.

---

## Step 3 — Verify everything works

Test in this order:

1. **Admin login** → code `ADMIN-001`, password from your `.env`
2. **Add a hospital** → Admin panel → Hospitals → Add Hospital
3. **Add a doctor** → Admin panel → Doctors → Add Doctor (select the hospital, add a phone number)
4. **Patient sign up** → Log out, open a new tab, sign up as a patient
5. **Book a token** → Browse hospitals → find the doctor → book
6. **Doctor login** → Log out, log in as Doctor with the new code format (`INITIALS.HOSPITAL.CITY.01`) + phone
7. **Regulate tokens** → Click tokens in the doctor dashboard — watch them update live in the patient tab

---

## API Reference

### Auth
| Method | Endpoint | Body | Auth |
|--------|----------|------|------|
| POST | `/api/auth/patient/signup` | `{name, email, password}` | — |
| POST | `/api/auth/patient/login` | `{email, password}` | — |
| POST | `/api/auth/doctor/login` | `{code, phone}` | — |
| POST | `/api/auth/admin/login` | `{code, password}` | — |
| GET | `/api/auth/me` | — | Bearer |

### Hospitals
| Method | Endpoint | Auth |
|--------|----------|------|
| GET | `/api/hospitals` | — |
| GET | `/api/hospitals/:id` | — |
| POST | `/api/hospitals` | Admin |
| PATCH | `/api/hospitals/:id` | Admin |
| POST | `/api/hospitals/:id/photo` | Admin (multipart/form-data) |
| DELETE | `/api/hospitals/:id` | Admin |

### Doctors
| Method | Endpoint | Auth |
|--------|----------|------|
| GET | `/api/doctors` | — |
| GET | `/api/doctors?hospitalId=X` | — |
| GET | `/api/doctors/:id` | — |
| POST | `/api/doctors` | Admin |
| PATCH | `/api/doctors/:id` | Doctor (own) or Admin |
| DELETE | `/api/doctors/:id` | Admin |

### Bookings
| Method | Endpoint | Auth |
|--------|----------|------|
| GET | `/api/bookings` | Bearer (filters by role) |
| GET | `/api/bookings/session/:sessionId` | Bearer |
| POST | `/api/bookings` | Patient |
| PATCH | `/api/bookings/:id/status` | Doctor/Admin |
| GET | `/api/bookings/stats/summary` | Admin |

### Token States
| Method | Endpoint | Auth |
|--------|----------|------|
| GET | `/api/tokens/:sessionId` | — |
| POST | `/api/tokens/:sessionId/regulate` | Doctor/Admin |
| POST | `/api/tokens/:sessionId/complete` | Doctor/Admin |
| POST | `/api/tokens/:sessionId/skip` | Doctor/Admin |
| POST | `/api/tokens/:sessionId/complete-skipped` | Doctor/Admin |
| POST | `/api/tokens/:sessionId/close` | Doctor/Admin |
| POST | `/api/tokens/:sessionId/priority-slot` | Doctor/Admin |
| POST | `/api/tokens/cancel-session` | Doctor/Admin |
| GET | `/api/tokens/cancelled/list` | — |

### WebSocket
Connect to: `ws://localhost:4000/ws?session=SESSION_ID`

Messages sent by server:
```json
{ "type": "state_update", "state": { ...SessionTokenState } }
{ "type": "token_booked", "sessionId": "...", "tokenNumber": 5 }
```

---

## Deploying to a server (production)

### Option A — VPS (DigitalOcean, Linode, Hetzner)

```bash
# On your server
git clone <your-repo> doctor-booked
cd doctor-booked/backend
npm install --production
cp .env.example .env
# Edit .env with production values

# Run with PM2 (keeps it alive)
npm install -g pm2
pm2 start src/index.js --name doctor-booked-api
pm2 startup
pm2 save

# Serve frontend build with nginx
cd ../src/frontend
pnpm install
pnpm build
# Point nginx to src/frontend/dist/
```

### Option B — Railway / Render (easiest)

1. Push the `backend/` folder to GitHub
2. Create a new Web Service on Railway or Render
3. Set environment variables from `.env.example`
4. Deploy — they auto-detect Node.js

For the frontend, deploy `src/frontend/dist/` to Vercel or Netlify.
Set `VITE_API_URL` to your backend's public URL before building.

### Nginx config (reverse proxy)

```nginx
server {
    listen 80;
    server_name yourdomain.com;

    # Frontend static files
    location / {
        root /var/www/doctor-booked/dist;
        try_files $uri $uri/ /index.html;
    }

    # Backend API + WebSocket
    location /api/ {
        proxy_pass http://localhost:4000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }

    location /ws {
        proxy_pass http://localhost:4000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }

    location /uploads/ {
        proxy_pass http://localhost:4000;
    }
}
```

---

## Security checklist before going live

- [ ] Change `JWT_SECRET` to a 64+ character random string
- [ ] Change `ADMIN_PASSWORD` to something strong
- [ ] Set `NODE_ENV=production` in `.env`
- [ ] Update `CORS_ORIGINS` to your real frontend domain only
- [ ] Enable HTTPS (use Let's Encrypt / Certbot)
- [ ] Set `VITE_API_URL` to `https://api.yourdomain.com/api`
- [ ] Back up your SQLite database file regularly
- [ ] If expecting > 1000 concurrent users, migrate from SQLite to PostgreSQL
