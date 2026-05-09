require('dotenv').config();
require('express-async-errors');

const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const morgan = require('morgan');

const { generalLimiter } = require('./middleware/rateLimiter');
const { errorHandler, notFound } = require('./middleware/errorHandler');

// Route imports
const authRoutes = require('./routes/auth');
const challengesRoutes = require('./routes/challenges');
const submissionsRoutes = require('./routes/submissions');
const usersRoutes = require('./routes/users');

const app = express();

// ─── Security Middleware ──────────────────────────────────────────────────────

app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        scriptSrc: ["'self'"],
        imgSrc: ["'self'", 'data:'],
      },
    },
    crossOriginEmbedderPolicy: false,
  })
);

app.use(
  cors({
    origin: process.env.FRONTEND_URL || 'http://localhost:5173',
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
  })
);

// ─── General Middleware ───────────────────────────────────────────────────────

app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));

if (process.env.NODE_ENV !== 'test') {
  app.use(morgan(process.env.NODE_ENV === 'production' ? 'combined' : 'dev'));
}

// Trust proxy for rate limiting behind Railway/Vercel
app.set('trust proxy', 1);

// Apply global rate limiter
app.use('/api', generalLimiter);

// ─── Health Check ─────────────────────────────────────────────────────────────

app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV,
    version: process.env.npm_package_version || '1.0.0',
  });
});

// ─── API Routes ───────────────────────────────────────────────────────────────

app.use('/api/auth', authRoutes);
app.use('/api/challenges', challengesRoutes);
app.use('/api/submissions', submissionsRoutes);
app.use('/api', usersRoutes); // /api/dashboard, /api/leaderboard, /api/users/:id/profile

// ─── Error Handling ───────────────────────────────────────────────────────────

app.use(notFound);
app.use(errorHandler);

// ─── Start Server ─────────────────────────────────────────────────────────────

const PORT = parseInt(process.env.PORT) || 3000;

if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`\n🚀 Server running on port ${PORT}`);
    console.log(`   Environment: ${process.env.NODE_ENV || 'development'}`);
    console.log(`   Health check: http://localhost:${PORT}/health`);
    console.log(`   API base:     http://localhost:${PORT}/api\n`);
  });
}

module.exports = app;
