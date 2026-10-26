const request = require('supertest');
const { validateConfig, getEnvironmentMode, isValidOrigin, parseCorsOrigins } = require('../src/config');
const app = require('../src/server');

describe('Demo Authentication App — Security Configuration & Startup Hardening', () => {
  const validProductionSecret = 'prod-strong-jwt-secret-with-high-entropy-64bytes-long-key';
  const validHmacSecret = 'prod-strong-hmac-secret-with-high-entropy-64bytes-long-key';
  const validOrigins = 'https://app.tokenline.io,https://dashboard.tokenline.io';

  describe('Environment Mode Resolution', () => {
    it('detects explicit development mode', () => {
      expect(getEnvironmentMode({ NODE_ENV: 'development' })).toBe('development');
      expect(getEnvironmentMode({ NODE_ENV: 'dev' })).toBe('development');
      expect(getEnvironmentMode({ NODE_ENV: 'local' })).toBe('development');
    });

    it('detects explicit test mode', () => {
      expect(getEnvironmentMode({ NODE_ENV: 'test' })).toBe('test');
      expect(getEnvironmentMode({ NODE_ENV: 'testing' })).toBe('test');
    });

    it('detects production mode', () => {
      expect(getEnvironmentMode({ NODE_ENV: 'production' })).toBe('production');
      expect(getEnvironmentMode({ NODE_ENV: 'prod' })).toBe('production');
    });

    it('enforces production when mode is unset (preventing silent fallback)', () => {
      expect(getEnvironmentMode({ NODE_ENV: '' })).toBe('production');
      expect(getEnvironmentMode({})).toBe('production');
    });

    it('detects misspelled/invalid modes to prevent silent dev fallback', () => {
      expect(getEnvironmentMode({ NODE_ENV: 'prdouction' })).toBe('invalid');
      expect(getEnvironmentMode({ NODE_ENV: 'staging' })).toBe('invalid');
      expect(getEnvironmentMode({ NODE_ENV: 'qa' })).toBe('invalid');
    });
  });

  describe('Production JWT & HMAC Secret Validation', () => {
    it('fails startup when JWT_SECRET is missing in production', () => {
      expect(() => {
        validateConfig({
          NODE_ENV: 'production',
          TOKEN_HMAC_SECRET: validHmacSecret,
          CORS_ALLOWED_ORIGINS: validOrigins,
        });
      }).toThrow(/JWT_SECRET must be explicitly configured in production/);
    });

    it('fails startup when JWT_SECRET is empty string in production', () => {
      expect(() => {
        validateConfig({
          NODE_ENV: 'production',
          JWT_SECRET: '   ',
          TOKEN_HMAC_SECRET: validHmacSecret,
          CORS_ALLOWED_ORIGINS: validOrigins,
        });
      }).toThrow(/JWT_SECRET must be explicitly configured in production/);
    });

    it('rejects known placeholder and default JWT secrets in production', () => {
      const placeholders = [
        'fallback_local_secret_do_not_use_in_prod',
        'super_secret_local_dev_key_only',
        'secret',
        'changeme',
        'password',
        'admin',
        'jwt-secret',
        'tokenline-admin-secret',
      ];
      for (const ph of placeholders) {
        expect(() => {
          validateConfig({
            NODE_ENV: 'production',
            JWT_SECRET: ph,
            TOKEN_HMAC_SECRET: validHmacSecret,
            CORS_ALLOWED_ORIGINS: validOrigins,
          });
        }).toThrow(/Insecure or placeholder JWT_SECRET is rejected/);
      }
    });

    it('rejects insufficiently strong JWT_SECRET in production (< 32 characters)', () => {
      expect(() => {
        validateConfig({
          NODE_ENV: 'production',
          JWT_SECRET: 'short-key-12345',
          TOKEN_HMAC_SECRET: validHmacSecret,
          CORS_ALLOWED_ORIGINS: validOrigins,
        });
      }).toThrow(/JWT_SECRET is insufficiently strong \(minimum 32 characters required in production\)/);
    });

    it('fails startup when TOKEN_HMAC_SECRET is missing in production', () => {
      expect(() => {
        validateConfig({
          NODE_ENV: 'production',
          JWT_SECRET: validProductionSecret,
          CORS_ALLOWED_ORIGINS: validOrigins,
        });
      }).toThrow(/TOKEN_HMAC_SECRET must be explicitly configured in production/);
    });

    it('rejects known placeholder and default TOKEN_HMAC_SECRET in production', () => {
      const placeholders = [
        'fallback_hmac_secret_do_not_use_in_prod',
        'fake-secret-for-demo-purposes-only',
        'secret',
        'changeme',
        'hmac-secret',
        'test-secret-key-123',
      ];
      for (const ph of placeholders) {
        expect(() => {
          validateConfig({
            NODE_ENV: 'production',
            JWT_SECRET: validProductionSecret,
            TOKEN_HMAC_SECRET: ph,
            CORS_ALLOWED_ORIGINS: validOrigins,
          });
        }).toThrow(/Insecure or placeholder TOKEN_HMAC_SECRET is rejected/);
      }
    });

    it('rejects insufficiently strong TOKEN_HMAC_SECRET in production (< 32 characters)', () => {
      expect(() => {
        validateConfig({
          NODE_ENV: 'production',
          JWT_SECRET: validProductionSecret,
          TOKEN_HMAC_SECRET: 'short-hmac-key-abc',
          CORS_ALLOWED_ORIGINS: validOrigins,
        });
      }).toThrow(/TOKEN_HMAC_SECRET is insufficiently strong \(minimum 32 characters required in production\)/);
    });

    it('rejects insecure fallback collector API keys in production', () => {
      expect(() => {
        validateConfig({
          NODE_ENV: 'production',
          JWT_SECRET: validProductionSecret,
          TOKEN_HMAC_SECRET: validHmacSecret,
          CORS_ALLOWED_ORIGINS: validOrigins,
          COLLECTOR_API_KEY: 'tokenline-ingest-secret',
        });
      }).toThrow(/Insecure or published default COLLECTOR_API_KEY is rejected in production/);
    });

    it('rejects weak collector API keys in production (< 16 characters)', () => {
      expect(() => {
        validateConfig({
          NODE_ENV: 'production',
          JWT_SECRET: validProductionSecret,
          TOKEN_HMAC_SECRET: validHmacSecret,
          CORS_ALLOWED_ORIGINS: validOrigins,
          COLLECTOR_API_KEY: 'short-key',
        });
      }).toThrow(/COLLECTOR_API_KEY is insufficiently strong/);
    });

    it('fails on misspelled environment mode settings', () => {
      expect(() => {
        validateConfig({
          NODE_ENV: 'prdouction',
          JWT_SECRET: validProductionSecret,
          TOKEN_HMAC_SECRET: validHmacSecret,
          CORS_ALLOWED_ORIGINS: validOrigins,
        });
      }).toThrow(/Unrecognized environment mode setting/);
    });

    it('does not disclose secret values in error messages', () => {
      const sensitiveKey = 'super-secret-password-12345678901234567890';
      try {
        validateConfig({
          NODE_ENV: 'production',
          JWT_SECRET: 'short',
          TOKEN_HMAC_SECRET: sensitiveKey,
          CORS_ALLOWED_ORIGINS: validOrigins,
        });
        throw new Error('Should have thrown validation error');
      } catch (err) {
        expect(err.message).not.toContain(sensitiveKey);
        expect(err.message).not.toContain('short');
      }
    });
  });

  describe('Production CORS Configuration Validation', () => {
    it('fails startup when CORS_ALLOWED_ORIGINS is missing in production', () => {
      expect(() => {
        validateConfig({
          NODE_ENV: 'production',
          JWT_SECRET: validProductionSecret,
          TOKEN_HMAC_SECRET: validHmacSecret,
        });
      }).toThrow(/CORS_ALLOWED_ORIGINS must be explicitly configured in production/);
    });

    it('fails startup when CORS_ALLOWED_ORIGINS is empty in production', () => {
      expect(() => {
        validateConfig({
          NODE_ENV: 'production',
          JWT_SECRET: validProductionSecret,
          TOKEN_HMAC_SECRET: validHmacSecret,
          CORS_ALLOWED_ORIGINS: '   ',
        });
      }).toThrow(/CORS_ALLOWED_ORIGINS must be explicitly configured in production/);
    });

    it('rejects wildcard origins in production', () => {
      expect(() => {
        validateConfig({
          NODE_ENV: 'production',
          JWT_SECRET: validProductionSecret,
          TOKEN_HMAC_SECRET: validHmacSecret,
          CORS_ALLOWED_ORIGINS: '*',
        });
      }).toThrow(/Wildcard CORS origins are forbidden in production/);

      expect(() => {
        validateConfig({
          NODE_ENV: 'production',
          JWT_SECRET: validProductionSecret,
          TOKEN_HMAC_SECRET: validHmacSecret,
          CORS_ALLOWED_ORIGINS: 'https://app.tokenline.io,*',
        });
      }).toThrow(/Wildcard CORS origins are forbidden in production/);
    });

    it('rejects malformed origins in production', () => {
      const malformed = [
        'not-a-url',
        'ftp://app.tokenline.io',
        'https://app.tokenline.io/path',
        'https://app.tokenline.io?query=1',
        'http://',
      ];
      for (const m of malformed) {
        expect(() => {
          validateConfig({
            NODE_ENV: 'production',
            JWT_SECRET: validProductionSecret,
            TOKEN_HMAC_SECRET: validHmacSecret,
            CORS_ALLOWED_ORIGINS: m,
          });
        }).toThrow(/Malformed CORS origin/);
      }
    });

    it('successfully starts with valid production configuration', () => {
      const cfg = validateConfig({
        NODE_ENV: 'production',
        JWT_SECRET: validProductionSecret,
        TOKEN_HMAC_SECRET: validHmacSecret,
        CORS_ALLOWED_ORIGINS: 'https://app.tokenline.io, https://dashboard.tokenline.io:8443',
        COLLECTOR_API_KEY: 'valid-strong-collector-key-32bytes',
      });
      expect(cfg.jwtSecret).toBe(validProductionSecret);
      expect(cfg.tokenHmacSecret).toBe(validHmacSecret);
      expect(cfg.corsAllowedOrigins).toEqual([
        'https://app.tokenline.io',
        'https://dashboard.tokenline.io:8443',
      ]);
      expect(cfg.collectorApiKey).toBe('valid-strong-collector-key-32bytes');
    });

    it('allows safe fixtures and defaults in explicit development/test mode', () => {
      const devCfg = validateConfig({ NODE_ENV: 'development' });
      expect(devCfg.jwtSecret).toBeTruthy();
      expect(devCfg.tokenHmacSecret).toBeTruthy();
      expect(devCfg.corsAllowedOrigins).toContain('http://localhost:3000');

      const testCfg = validateConfig({ NODE_ENV: 'test' });
      expect(testCfg.jwtSecret).toBeTruthy();
      expect(testCfg.tokenHmacSecret).toBeTruthy();
    });
  });

  describe('CORS Enforcement on HTTP Endpoints', () => {
    it('grants CORS access to configured allowed origins', async () => {
      const res = await request(app)
        .post('/auth/login')
        .set('Origin', 'http://localhost:3000')
        .send({ username: 'demo-user', password: 'wrongpassword' });

      expect(res.headers['access-control-allow-origin']).toBe('http://localhost:3000');
      expect(res.headers['access-control-allow-methods']).toContain('GET, POST, OPTIONS');
      expect(res.headers['access-control-allow-headers']).toContain('Authorization');
      expect(res.headers['access-control-allow-headers']).toContain('X-API-Key');
    });

    it('does not grant CORS access to unconfigured origins', async () => {
      const res = await request(app)
        .post('/auth/login')
        .set('Origin', 'https://untrusted-attacker.com')
        .send({ username: 'demo-user', password: 'wrongpassword' });

      expect(res.headers['access-control-allow-origin']).toBeUndefined();
    });

    it('handles legitimate CORS preflight OPTIONS requests for configured origins', async () => {
      const res = await request(app)
        .options('/auth/login')
        .set('Origin', 'http://localhost:3000')
        .set('Access-Control-Request-Method', 'POST')
        .set('Access-Control-Request-Headers', 'Content-Type, Authorization, X-API-Key');

      expect(res.statusCode).toBe(204);
      expect(res.headers['access-control-allow-origin']).toBe('http://localhost:3000');
      expect(res.headers['access-control-allow-methods']).toContain('POST');
      expect(res.headers['access-control-allow-headers']).toContain('Authorization');
      expect(res.headers['access-control-allow-headers']).toContain('X-API-Key');
    });

    it('rejects CORS preflight OPTIONS requests from untrusted origins with 403', async () => {
      const res = await request(app)
        .options('/auth/login')
        .set('Origin', 'https://untrusted-attacker.com')
        .set('Access-Control-Request-Method', 'POST');

      expect(res.statusCode).toBe(403);
      expect(res.headers['access-control-allow-origin']).toBeUndefined();
    });
  });
});
