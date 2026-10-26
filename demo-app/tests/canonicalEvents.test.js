const request = require('supertest');
const app = require('../src/server');
const eventService = require('../src/services/eventService');
const config = require('../src/config');
const { hashToken } = require('../src/utils/tokenId');

// Mock fetch for eventService
const originalFetch = global.fetch;
let mockFetchCalls = [];

beforeEach(() => {
  mockFetchCalls = [];
  global.fetch = jest.fn((url, options) => {
    mockFetchCalls.push({ url, options });
    return Promise.resolve({
      ok: true,
      status: 201,
      text: () => Promise.resolve('{"status":"event persisted"}'),
      json: () => Promise.resolve({ status: 'event persisted' }),
    });
  });
});

afterAll(() => {
  global.fetch = originalFetch;
});

describe('Canonical Event Generation & Collector Delivery Integration', () => {

  it('1. Failed login emits canonical login_failed (rejected) and NEVER replay_detected', async () => {
    const res = await request(app)
      .post('/auth/login')
      .send({ username: 'demo-user', password: 'WrongPassword999!' });

    expect(res.statusCode).toBe(401);
    expect(mockFetchCalls.length).toBeGreaterThan(0);

    const emittedPayloads = mockFetchCalls.map(c => JSON.parse(c.options.body));
    const loginFailEvt = emittedPayloads.find(e => e.event_type === 'login_failed');

    expect(loginFailEvt).toBeDefined();
    expect(loginFailEvt.event_type).toBe('login_failed');
    expect(loginFailEvt.result).toBe('rejected');
    expect(loginFailEvt.user_id).toBe('user_synthetic_001');
    // token_hash must NOT be fabricated for login_failed
    expect(loginFailEvt.token_hash).toBeUndefined();
    expect(loginFailEvt.token_family).toBeUndefined();
    // Must NOT contain replay_detected
    const replayEvt = emittedPayloads.find(e => e.event_type === 'replay_detected');
    expect(replayEvt).toBeUndefined();
  });

  it('2. Successful login emits canonical token_issued with genuine context', async () => {
    const res = await request(app)
      .post('/auth/login')
      .send({ username: 'demo-user', password: 'DemoPassword123!' });

    expect(res.statusCode).toBe(200);

    const emittedPayloads = mockFetchCalls.map(c => JSON.parse(c.options.body));
    const tokenIssuedEvt = emittedPayloads.find(e => e.event_type === 'token_issued');

    expect(tokenIssuedEvt).toBeDefined();
    expect(tokenIssuedEvt.result).toBe('accepted');
    expect(tokenIssuedEvt.user_id).toBe('user_synthetic_001');
    expect(tokenIssuedEvt.token_hash).toBeDefined();
    expect(tokenIssuedEvt.token_hash).not.toBe('root-token'); // Not synthetic
    expect(tokenIssuedEvt.token_family).not.toBe('family-unknown'); // Not synthetic
    expect(tokenIssuedEvt.endpoint).toBe('/auth/login');
    expect(tokenIssuedEvt.source).toBe('demo_app');
    expect(tokenIssuedEvt.is_simulation).toBe(false);
  });

  it('3. Failed refresh token emits token_rejected and NEVER replay_detected', async () => {
    const res = await request(app)
      .post('/auth/refresh')
      .send({ refreshToken: 'non-existent-refresh-token' });

    expect(res.statusCode).toBe(401);

    const emittedPayloads = mockFetchCalls.map(c => JSON.parse(c.options.body));
    const rejectedEvt = emittedPayloads.find(e => e.event_type === 'token_rejected');

    expect(rejectedEvt).toBeDefined();
    expect(rejectedEvt.result).toBe('rejected');
    expect(rejectedEvt.event_type).toBe('token_rejected');

    const replayEvt = emittedPayloads.find(e => e.event_type === 'replay_detected');
    expect(replayEvt).toBeUndefined();
  });

  it('4. Reused refresh token emits refresh_reuse_detected', async () => {
    // Login to obtain valid tokens
    const loginRes = await request(app)
      .post('/auth/login')
      .send({ username: 'demo-user', password: 'DemoPassword123!' });
    const originalRefreshToken = loginRes.body.refreshToken;

    // First refresh rotates originalRefreshToken
    await request(app)
      .post('/auth/refresh')
      .send({ refreshToken: originalRefreshToken });

    mockFetchCalls = [];

    // Second refresh with already-rotated token triggers reuse detection
    const reuseRes = await request(app)
      .post('/auth/refresh')
      .send({ refreshToken: originalRefreshToken });

    expect(reuseRes.statusCode).toBe(401);

    const emittedPayloads = mockFetchCalls.map(c => JSON.parse(c.options.body));
    const reuseEvt = emittedPayloads.find(e => e.event_type === 'refresh_reuse_detected');

    expect(reuseEvt).toBeDefined();
    expect(reuseEvt.result).toBe('rejected');
    expect(reuseEvt.token_hash).toBe(hashToken(originalRefreshToken));
  });

  it('5. Authenticated collector delivery includes X-API-Key header', async () => {
    config.collectorApiKey = 'test-ingest-api-key';

    await eventService.emit('token_issued', {
      userId: 'test-user',
      tokenIdentifier: 'a4d3b8f1c29e4b7a11d2e3f4',
      tokenFamilyId: 'fam-123',
      deviceId: 'dev-1',
      endpoint: '/auth/login',
      ip: '127.0.0.1'
    });

    expect(mockFetchCalls.length).toBeGreaterThan(0);
    const lastCall = mockFetchCalls[mockFetchCalls.length - 1];
    expect(lastCall.options.headers['X-API-Key']).toBe('test-ingest-api-key');
  });

  it('6. Collector HTTP 400 schema rejection is handled without retrying', async () => {
    global.fetch = jest.fn(() =>
      Promise.resolve({
        ok: false,
        status: 400,
        text: () => Promise.resolve('Schema validation failed: invalid format'),
      })
    );

    const result = await eventService.sendToCollector({
      event_id: 'evt-bad-01',
      event_type: 'token_issued',
      time: '2026-10-26T14:00:00Z',
      user_id: 'user-1',
      ip_hash: 'e3b0c44298fc1c14',
      device_id: 'dev-1',
      result: 'accepted'
    });

    expect(result.success).toBe(false);
    expect(result.status).toBe(400);
    expect(result.retryable).toBe(false);
    // Schema rejection must NOT be retried
    expect(global.fetch).toHaveBeenCalledTimes(1);
  });

  it('7. Collector HTTP 401 authentication failure is handled without exposing credentials', async () => {
    global.fetch = jest.fn(() =>
      Promise.resolve({
        ok: false,
        status: 401,
        text: () => Promise.resolve('Unauthorized: Invalid credentials'),
      })
    );

    const result = await eventService.sendToCollector({
      event_id: 'evt-auth-fail-01',
      event_type: 'token_issued',
      time: '2026-10-26T14:00:00Z',
      user_id: 'user-1',
      ip_hash: 'e3b0c44298fc1c14',
      device_id: 'dev-1',
      result: 'accepted'
    });

    expect(result.success).toBe(false);
    expect(result.status).toBe(401);
    expect(result.retryable).toBe(false);
    expect(global.fetch).toHaveBeenCalledTimes(1);
  });

  it('8. Server error (HTTP 500) triggers bounded retries', async () => {
    let callCount = 0;
    global.fetch = jest.fn(() => {
      callCount++;
      return Promise.resolve({
        ok: false,
        status: 500,
        text: () => Promise.resolve('Internal Server Error'),
      });
    });

    const result = await eventService.sendToCollector({
      event_id: 'evt-retry-01',
      event_type: 'token_issued',
      time: '2026-10-26T14:00:00Z',
      user_id: 'user-1',
      ip_hash: 'e3b0c44298fc1c14',
      device_id: 'dev-1',
      result: 'accepted'
    });

    expect(result.success).toBe(false);
    // Bounded retries: initial attempt + 2 retries = 3 calls total
    expect(callCount).toBe(3);
  });
});
