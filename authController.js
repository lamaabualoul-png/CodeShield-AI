const bcrypt = require('bcryptjs');
const { query } = require('../db');
const { generateTokenPair, verifyToken, hashToken } = require('../utils/jwt');

const BCRYPT_ROUNDS = 12;

/**
 * POST /api/auth/register
 */
const register = async (req, res) => {
  const { username, email, password } = req.body;

  // Hash password
  const password_hash = await bcrypt.hash(password, BCRYPT_ROUNDS);

  // Insert user
  const result = await query(
    `INSERT INTO users (username, email, password_hash)
     VALUES ($1, $2, $3)
     RETURNING id, username, email, role, created_at`,
    [username.trim(), email.toLowerCase().trim(), password_hash]
  );

  const user = result.rows[0];
  const { accessToken, refreshToken } = generateTokenPair(user);

  // Store refresh token hash
  await storeRefreshToken(user.id, refreshToken);

  return res.status(201).json({
    message: 'Account created successfully',
    user: {
      id: user.id,
      username: user.username,
      email: user.email,
      role: user.role,
    },
    accessToken,
    refreshToken,
  });
};

/**
 * POST /api/auth/login
 */
const login = async (req, res) => {
  const { email, password } = req.body;

  // Fetch user (use a timing-safe pattern)
  const result = await query(
    'SELECT id, username, email, password_hash, role FROM users WHERE email = $1',
    [email.toLowerCase().trim()]
  );

  const user = result.rows[0];

  // Always run bcrypt.compare to prevent timing attacks (even if user not found)
  const dummyHash = '$2b$12$invalidhashfortimingattackprevention000000000000000000';
  const passwordMatch = await bcrypt.compare(
    password,
    user ? user.password_hash : dummyHash
  );

  if (!user || !passwordMatch) {
    return res.status(401).json({
      error: 'InvalidCredentials',
      message: 'Invalid email or password',
    });
  }

  const { accessToken, refreshToken } = generateTokenPair(user);
  await storeRefreshToken(user.id, refreshToken);

  return res.json({
    message: 'Login successful',
    user: {
      id: user.id,
      username: user.username,
      email: user.email,
      role: user.role,
    },
    accessToken,
    refreshToken,
  });
};

/**
 * POST /api/auth/refresh
 */
const refresh = async (req, res) => {
  const { refreshToken } = req.body;

  if (!refreshToken) {
    return res.status(400).json({ error: 'BadRequest', message: 'Refresh token required' });
  }

  let decoded;
  try {
    decoded = verifyToken(refreshToken);
  } catch {
    return res.status(401).json({ error: 'InvalidToken', message: 'Refresh token is invalid or expired' });
  }

  // Check if token is in the database (not revoked)
  const tokenHash = hashToken(refreshToken);
  const stored = await query(
    'SELECT id FROM refresh_tokens WHERE user_id = $1 AND token_hash = $2 AND expires_at > NOW()',
    [decoded.sub, tokenHash]
  );

  if (stored.rowCount === 0) {
    return res.status(401).json({ error: 'InvalidToken', message: 'Refresh token has been revoked' });
  }

  // Rotate: delete old, issue new
  await query('DELETE FROM refresh_tokens WHERE token_hash = $1', [tokenHash]);

  const userResult = await query(
    'SELECT id, username, email, role FROM users WHERE id = $1',
    [decoded.sub]
  );

  if (userResult.rowCount === 0) {
    return res.status(401).json({ error: 'InvalidToken', message: 'User no longer exists' });
  }

  const user = userResult.rows[0];
  const { accessToken, refreshToken: newRefreshToken } = generateTokenPair(user);
  await storeRefreshToken(user.id, newRefreshToken);

  return res.json({ accessToken, refreshToken: newRefreshToken });
};

/**
 * POST /api/auth/logout
 */
const logout = async (req, res) => {
  const { refreshToken } = req.body;

  if (refreshToken) {
    const tokenHash = hashToken(refreshToken);
    await query('DELETE FROM refresh_tokens WHERE token_hash = $1', [tokenHash]);
  }

  return res.json({ message: 'Logged out successfully' });
};

/**
 * GET /api/auth/me — returns current user info
 */
const me = async (req, res) => {
  const result = await query(
    'SELECT id, username, email, role, total_score, challenges_completed, created_at FROM users WHERE id = $1',
    [req.user.id]
  );

  if (result.rowCount === 0) {
    return res.status(404).json({ error: 'NotFound', message: 'User not found' });
  }

  return res.json({ user: result.rows[0] });
};

// ─── Helpers ───────────────────────────────────────────────────────────────

const storeRefreshToken = async (userId, token) => {
  const tokenHash = hashToken(token);
  const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days

  await query(
    'INSERT INTO refresh_tokens (user_id, token_hash, expires_at) VALUES ($1, $2, $3)',
    [userId, tokenHash, expiresAt]
  );

  // Housekeeping: remove expired tokens for this user
  await query(
    'DELETE FROM refresh_tokens WHERE user_id = $1 AND expires_at < NOW()',
    [userId]
  );
};

module.exports = { register, login, refresh, logout, me };
