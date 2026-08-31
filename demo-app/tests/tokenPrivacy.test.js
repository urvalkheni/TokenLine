const { hashToken } = require('../src/utils/tokenId');
const config = require('../src/config');
const eventService = require('../src/services/eventService');
const crypto = require('crypto');

// Mock fetch for eventService
global.fetch = jest.fn(() =>
  Promise.resolve({
    ok: true,
    json: () => Promise.resolve({}),
  })
);

describe('Token Privacy Utility', () => {
  const originalSecret = config.tokenHmacSecret;

  beforeEach(() => {
    config.tokenHmacSecret = 'test-secret-key-123';
  });

  afterAll(() => {
    config.tokenHmacSecret = originalSecret;
  });

  it('Test 1 - Deterministic identifier: same token and secret -> same token_hash', () => {
    const token = 'my-super-secret-token-1';
    const hash1 = hashToken(token);
    const hash2 = hashToken(token);
    expect(hash1).toBe(hash2);
  });

  it('Test 2 - Different tokens produce distinct identifiers', () => {
    const token1 = 'token-A';
    const token2 = 'token-B';
    const hash1 = hashToken(token1);
    const hash2 = hashToken(token2);
    expect(hash1).not.toBe(hash2);
  });

  it('Test 3 - Raw token is not recoverable/returned in the hash', () => {
    const token = 'unique-raw-token-42';
    const hash = hashToken(token);
    expect(hash).not.toContain(token);
    expect(hash).not.toBe(token);
  });

  it('Test 4 - HMAC behavior: changing secret changes identifier', () => {
    const token = 'another-token';
    const hash1 = hashToken(token);

    config.tokenHmacSecret = 'different-secret-key';
    const hash2 = hashToken(token);

    expect(hash1).not.toBe(hash2);
  });

  it('Test 5 - Empty/invalid input handling', () => {
    expect(() => hashToken('')).not.toThrow();
    // Typical crypto error when passing undefined
    expect(() => hashToken(undefined)).toThrow(); 
    expect(() => hashToken(null)).toThrow();
  });
});

describe('Token Logging and Persistence Security', () => {
  const originalLog = console.log;
  let consoleLogs = [];

  beforeEach(() => {
    consoleLogs = [];
    console.log = (...args) => {
      consoleLogs.push(args.join(' '));
    };
    fetch.mockClear();
  });

  afterEach(() => {
    console.log = originalLog;
  });

  it('Test 11 - Required logging security test', () => {
    const syntheticToken = 'synthetic-test-token-12345';
    
    // Simulate an event emission where a raw token is accidentally passed
    eventService.emit('token_issued', {
      userId: 'test-user',
      tokenIdentifier: hashToken(syntheticToken),
      rawToken: syntheticToken, // accidentally passing raw token
      accessToken: 'acc-synthetic-test-token-12345', // accidentally passing another raw token
    });

    const logsString = consoleLogs.join('\n');
    
    // Assert raw tokens NEVER appear in logs
    expect(logsString).not.toContain(syntheticToken);
    expect(logsString).not.toContain('acc-synthetic-test-token-12345');
    
    // Assert the safe token identifier IS allowed in the log
    expect(logsString).toContain(hashToken(syntheticToken));
  });

  it('Test 12 - Persistence test', () => {
    const syntheticToken = 'synthetic-test-token-67890';
    const safeHash = hashToken(syntheticToken);

    // Emit event with raw token accidentally included
    eventService.emit('token_issued', {
      userId: 'test-user',
      tokenIdentifier: safeHash,
      rawToken: syntheticToken,
    });

    // Check what was sent to the collector via fetch
    expect(fetch).toHaveBeenCalledTimes(1);
    
    const fetchCall = fetch.mock.calls[0];
    const requestBody = JSON.parse(fetchCall[1].body);

    // Assert that token_hash is persisted
    expect(requestBody.token_hash).toBe(safeHash);

    // Assert that raw token is NOT persisted
    expect(requestBody.rawToken).toBeUndefined();
    const stringifiedBody = JSON.stringify(requestBody);
    expect(stringifiedBody).not.toContain(syntheticToken);
  });
});
