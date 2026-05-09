const { test, expect } = require('@playwright/test');

const API = 'http://localhost:3000/api';
const timestamp = Date.now();
const testUser = {
  username: `testuser_${timestamp}`,
  email: `test_${timestamp}@example.com`,
  password: 'TestPass123',
};

let accessToken = '';
let refreshToken = '';
let userId = '';

test.describe('Authentication Flow', () => {
  test('Health check passes', async ({ request }) => {
    const res = await request.get('http://localhost:3000/health');
    expect(res.status()).toBe(200);
    const body = await res.json();
    expect(body.status).toBe('ok');
  });

  test('Register a new user', async ({ request }) => {
    const res = await request.post(`${API}/auth/register`, {
      data: testUser,
    });

    expect(res.status()).toBe(201);
    const body = await res.json();

    expect(body).toHaveProperty('accessToken');
    expect(body).toHaveProperty('refreshToken');
    expect(body.user.email).toBe(testUser.email);
    expect(body.user).not.toHaveProperty('password_hash');

    accessToken = body.accessToken;
    refreshToken = body.refreshToken;
    userId = body.user.id;
  });

  test('Duplicate registration is rejected', async ({ request }) => {
    const res = await request.post(`${API}/auth/register`, {
      data: testUser,
    });
    expect(res.status()).toBe(409);
  });

  test('Registration with weak password fails', async ({ request }) => {
    const res = await request.post(`${API}/auth/register`, {
      data: { username: 'newuser', email: 'new@example.com', password: 'weak' },
    });
    expect(res.status()).toBe(422);
    const body = await res.json();
    expect(body.error).toBe('ValidationError');
  });

  test('Login with valid credentials', async ({ request }) => {
    const res = await request.post(`${API}/auth/login`, {
      data: { email: testUser.email, password: testUser.password },
    });

    expect(res.status()).toBe(200);
    const body = await res.json();
    expect(body).toHaveProperty('accessToken');
    accessToken = body.accessToken;
  });

  test('Login with wrong password is rejected', async ({ request }) => {
    const res = await request.post(`${API}/auth/login`, {
      data: { email: testUser.email, password: 'WrongPassword999' },
    });
    expect(res.status()).toBe(401);
    const body = await res.json();
    expect(body.error).toBe('InvalidCredentials');
  });

  test('GET /auth/me returns authenticated user', async ({ request }) => {
    const res = await request.get(`${API}/auth/me`, {
      headers: { Authorization: `Bearer ${accessToken}` },
    });
    expect(res.status()).toBe(200);
    const body = await res.json();
    expect(body.user.id).toBe(userId);
    expect(body.user).not.toHaveProperty('password_hash');
  });

  test('GET /auth/me without token returns 401', async ({ request }) => {
    const res = await request.get(`${API}/auth/me`);
    expect(res.status()).toBe(401);
  });

  test('Refresh token rotates successfully', async ({ request }) => {
    const res = await request.post(`${API}/auth/refresh`, {
      data: { refreshToken },
    });
    expect(res.status()).toBe(200);
    const body = await res.json();
    expect(body).toHaveProperty('accessToken');
    expect(body).toHaveProperty('refreshToken');
    expect(body.refreshToken).not.toBe(refreshToken); // Token was rotated
    accessToken = body.accessToken;
    refreshToken = body.refreshToken;
  });

  test('Logout invalidates refresh token', async ({ request }) => {
    await request.post(`${API}/auth/logout`, {
      data: { refreshToken },
    });

    // Try to use the revoked refresh token
    const res = await request.post(`${API}/auth/refresh`, {
      data: { refreshToken },
    });
    expect(res.status()).toBe(401);
  });
});
