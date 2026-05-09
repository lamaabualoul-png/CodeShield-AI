# Code Analyzer — Backend API

A secure Node.js/Express REST API for the AI Code Analyzer Platform. Covers all course requirements: JWT authentication (W10), dashboard (W8), testing (W9), security (W12), and deployment (W11).

---

## Tech Stack

- **Runtime:** Node.js + Express
- **Database:** PostgreSQL (via `pg`)
- **Auth:** JWT (access + refresh token rotation)
- **AI:** OpenAI GPT-4o-mini (with mock fallback)
- **Security:** Helmet, CORS, bcrypt, express-rate-limit, express-validator, xss
- **Testing:** Playwright (API tests)
- **Deployment:** Railway (backend) + PostgreSQL add-on

---

## Project Structure

```
src/
├── index.js              # App entry point, middleware setup
├── db/
│   ├── index.js          # PostgreSQL connection pool
│   ├── migrate.js        # Run DB migrations
│   └── seed.js           # Seed challenges
├── routes/
│   ├── auth.js           # /api/auth/*
│   ├── challenges.js     # /api/challenges/*
│   ├── submissions.js    # /api/submissions/*
│   └── users.js          # /api/dashboard, /api/leaderboard
├── controllers/
│   ├── authController.js
│   ├── challengesController.js
│   ├── submissionsController.js
│   └── dashboardController.js
├── middleware/
│   ├── auth.js           # JWT verify, role guards
│   ├── rateLimiter.js    # Rate limit configs
│   ├── validation.js     # express-validator rules
│   └── errorHandler.js   # Centralized error handler
├── services/
│   └── aiService.js      # OpenAI integration + mock analyzer
└── utils/
    ├── jwt.js            # Token generation/verification
    └── sanitize.js       # Input sanitization helpers
tests/
├── auth.spec.js          # Login/register/refresh/logout tests
├── submissions.spec.js   # Code submission + AI analysis tests
└── dashboard.spec.js     # Dashboard + security tests
```

---

## Quick Start

### 1. Install dependencies
```bash
npm install
```

### 2. Configure environment
```bash
cp .env.example .env
# Edit .env with your DB URL, JWT secret, OpenAI key
```

### 3. Run database migrations
```bash
npm run db:migrate
```

### 4. Seed challenges
```bash
npm run db:seed
```

### 5. Start the server
```bash
npm run dev   # Development with hot reload
npm start     # Production
```

---

## API Endpoints

### Auth  (`/api/auth`)
| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/register` | — | Create account |
| POST | `/login` | — | Login, get tokens |
| POST | `/refresh` | — | Rotate refresh token |
| POST | `/logout` | — | Revoke refresh token |
| GET | `/me` | ✅ | Get current user |

### Challenges  (`/api/challenges`)
| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/` | — | List challenges (filter by difficulty/language) |
| GET | `/:id` | — | Get challenge + starter code |
| POST | `/` | Admin | Create challenge |
| PATCH | `/:id` | Admin | Update challenge |

### Submissions  (`/api/submissions`)
| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/` | ✅ | Submit code → AI analysis |
| GET | `/` | ✅ | List my submissions |
| GET | `/:id` | ✅ | Get submission + feedback |

### Dashboard & Users
| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/dashboard` | ✅ | Full dashboard data |
| GET | `/api/leaderboard` | — | Top users by score |
| GET | `/api/users/:id/profile` | — | Public user profile |

---

## Security Features (W12)

- **JWT authentication** with access/refresh token rotation
- **Password hashing** with bcrypt (12 rounds)
- **Parameterized queries** everywhere — no SQL injection possible
- **Input validation** with express-validator on all endpoints
- **XSS sanitization** via `xss` library
- **Rate limiting:** 100 req/15min general, 10/15min for auth, 20/hr for AI
- **Helmet** sets secure HTTP headers (CSP, HSTS, etc.)
- **CORS** configured to allow only the frontend origin
- **Timing-safe** login (always runs bcrypt.compare to prevent user enumeration)
- **Refresh token hashing** — raw tokens never stored in DB

---

## Testing (W9)

```bash
# Run all Playwright tests (server must be running)
npm test

# Run specific test file
npx playwright test tests/auth.spec.js
```

**Test coverage:**
- Auth: register, login, refresh, logout, protected route access
- Submissions: submit code, AI feedback structure, auth guards
- Dashboard: stats, leaderboard
- Security: SQL injection attempt, XSS in username, oversized payload, fake tokens, RBAC

---

## Deployment (W11)

### Railway (Backend + DB)

1. Create a Railway project
2. Add a **PostgreSQL** service → copy `DATABASE_URL`
3. Add a **Web Service** from this repo
4. Set environment variables:
   ```
   NODE_ENV=production
   DATABASE_URL=<from Railway PostgreSQL>
   JWT_SECRET=<generate: openssl rand -hex 64>
   OPENAI_API_KEY=<your key>
   FRONTEND_URL=<your Vercel frontend URL>
   ```
5. Railway auto-deploys on git push
6. After first deploy, run migrations:
   ```bash
   railway run npm run db:migrate
   railway run npm run db:seed
   ```

### Health Check
`GET /health` — Railway uses this to confirm the service is up.

---

## AI Analysis Response Format

```json
{
  "submission": {
    "id": "uuid",
    "score": 45,
    "max_score": 100,
    "status": "analyzed",
    "summary": "Found 2 security issues and 1 bug that need attention.",
    "errors": [
      { "line": 8, "severity": "warning", "type": "missing_error_handling", "message": "...", "fix": "..." }
    ],
    "security_issues": [
      { "line": 3, "severity": "critical", "type": "A03:2021-Injection", "message": "...", "fix": "..." }
    ],
    "suggestions": [
      { "type": "documentation", "message": "...", "example": "..." }
    ]
  }
}
```
