const request = require('supertest');
const app = require('../src/server');

// Mock console.log to test what is being logged
const originalLog = console.log;
let consoleLogs = [];

beforeEach(() => {
  consoleLogs = [];
  console.log = (...args) => {
    consoleLogs.push(args.join(' '));
  };
});

afterEach(() => {
  console.log = originalLog;
});

describe('Authentication Flow', () => {
  let accessToken;
  let refreshToken;
  let sessionId;

  it('should fail login with invalid credentials', async () => {
    const res = await request(app)
      .post('/auth/login')
      .send({ username: 'demo-user', password: 'wrongpassword' });
    
    expect(res.statusCode).toBe(401);
    expect(res.body).toHaveProperty('error');
  });

  it('should login successfully with valid credentials', async () => {
    const res = await request(app)
      .post('/auth/login')
      .send({ username: 'demo-user', password: 'DemoPassword123!' });
    
    expect(res.statusCode).toBe(200);
    expect(res.body).toHaveProperty('accessToken');
    expect(res.body).toHaveProperty('refreshToken');
    expect(res.body).toHaveProperty('sessionId');

    accessToken = res.body.accessToken;
    refreshToken = res.body.refreshToken;
    sessionId = res.body.sessionId;
  });

  it('should not log raw tokens or passwords during login', () => {
    const logsString = consoleLogs.join('\n');
    expect(logsString).not.toContain('DemoPassword123!');
    expect(logsString).not.toContain(accessToken);
    expect(logsString).not.toContain(refreshToken);
  });

  it('should fail to access protected API without token', async () => {
    const res = await request(app)
      .get('/api/profile');
    
    expect(res.statusCode).toBe(401);
  });

  it('should access protected API with valid access token', async () => {
    const res = await request(app)
      .get('/api/profile')
      .set('Authorization', `Bearer ${accessToken}`);
    
    expect(res.statusCode).toBe(200);
    expect(res.body.user).toHaveProperty('username', 'demo-user');
  });

  it('should refresh tokens successfully', async () => {
    const res = await request(app)
      .post('/auth/refresh')
      .send({ refreshToken });
    
    expect(res.statusCode).toBe(200);
    expect(res.body).toHaveProperty('accessToken');
    expect(res.body).toHaveProperty('refreshToken');
    expect(res.body.accessToken).not.toBe(accessToken);
    expect(res.body.refreshToken).not.toBe(refreshToken);

    accessToken = res.body.accessToken;
    // Keep the old one around to test reuse detection
    const oldRefreshToken = refreshToken;
    refreshToken = res.body.refreshToken;

    // Test refresh reuse
    const reuseRes = await request(app)
      .post('/auth/refresh')
      .send({ refreshToken: oldRefreshToken });
    
    expect(reuseRes.statusCode).toBe(401);
    expect(reuseRes.body.error).toContain('suspicious activity');
  });

  it('should reject access to protected API after token family revoked due to reuse', async () => {
    const res = await request(app)
      .get('/api/profile')
      .set('Authorization', `Bearer ${accessToken}`);
    
    // Because session was revoked during the reuse attempt
    expect(res.statusCode).toBe(401);
    expect(res.body.error).toContain('revoked');
  });

  it('should handle standard logout', async () => {
    // Relogin to get a fresh session
    const loginRes = await request(app)
      .post('/auth/login')
      .send({ username: 'demo-user', password: 'DemoPassword123!' });
    
    const freshAccessToken = loginRes.body.accessToken;

    const logoutRes = await request(app)
      .post('/auth/logout')
      .set('Authorization', `Bearer ${freshAccessToken}`);
    
    expect(logoutRes.statusCode).toBe(200);

    // Try accessing protected API after logout
    const protectedRes = await request(app)
      .get('/api/profile')
      .set('Authorization', `Bearer ${freshAccessToken}`);
    
    expect(protectedRes.statusCode).toBe(401);
  });
});
