require('dotenv').config();

/**
 * List of known default, published, or placeholder secrets that must never
 * be accepted in production environments.
 */
const INSECURE_SECRETS = new Set([
  'fallback_local_secret_do_not_use_in_prod',
  'fallback_hmac_secret_do_not_use_in_prod',
  'super_secret_local_dev_key_only',
  'fake-secret-for-demo-purposes-only',
  'tokenline-admin-secret',
  'tokenline-ingest-secret',
  'tokenline-read-secret',
  'secret',
  'changeme',
  'password',
  '123456',
  'admin',
  'default',
  'jwt-secret',
  'hmac-secret',
  'test-secret-key-123',
]);

/**
 * Resolves the active environment mode.
 * Returns 'production', 'development', 'test', or 'invalid'.
 */
function getEnvironmentMode(envObj = process.env) {
  const env = (
    envObj.TOKENLINE_ENV ||
    envObj.NODE_ENV ||
    envObj.APP_ENV ||
    envObj.ENV ||
    ''
  ).trim().toLowerCase();

  if (['development', 'dev', 'local'].includes(env)) {
    return 'development';
  }
  if (['test', 'testing'].includes(env)) {
    return 'test';
  }
  if (['production', 'prod'].includes(env)) {
    return 'production';
  }
  if (env === '') {
    // When mode is unset, production mode is enforced to prevent silent fallback to dev
    return 'production';
  }
  return 'invalid';
}

/**
 * Validates that an origin string is a valid RFC 6454 HTTP/HTTPS origin.
 * Must not contain path (other than optional root /), query, or hash.
 */
function isValidOrigin(originStr) {
  if (!originStr || typeof originStr !== 'string') return false;
  const s = originStr.trim();
  if (s === '*') return false;
  try {
    const parsed = new URL(s);
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return false;
    if (parsed.pathname && parsed.pathname !== '/') return false;
    if (parsed.search || parsed.hash) return false;
    if (parsed.username || parsed.password) return false;
    if (!parsed.host) return false;
    if (parsed.origin !== s && `${parsed.origin}/` !== s) return false;
    return true;
  } catch {
    return false;
  }
}

/**
 * Parses raw CORS allowed origins input into a list of strings.
 */
function parseCorsOrigins(originsVal) {
  if (!originsVal) return [];
  if (Array.isArray(originsVal)) {
    return originsVal.map(o => String(o).trim()).filter(Boolean);
  }
  const s = String(originsVal).trim();
  if (s.startsWith('[') && s.endsWith(']')) {
    try {
      const parsed = JSON.parse(s);
      if (Array.isArray(parsed)) {
        return parsed.map(o => String(o).trim()).filter(Boolean);
      }
    } catch {
      // Fall through to comma-separated parsing
    }
  }
  return s.split(',').map(o => o.trim()).filter(Boolean);
}

/**
 * Validates environment configuration according to execution mode.
 * Throws descriptive configuration errors without disclosing secret values.
 */
function validateConfig(envObj = process.env) {
  const mode = getEnvironmentMode(envObj);
  const isDevOrTest = mode === 'development' || mode === 'test';

  if (mode === 'invalid') {
    throw new Error(
      'Configuration error: Unrecognized environment mode setting. Production mode required or explicitly set to development/test.'
    );
  }

  let jwtSecret = envObj.JWT_SECRET;
  let tokenHmacSecret = envObj.TOKEN_HMAC_SECRET;
  const rawCors = envObj.CORS_ALLOWED_ORIGINS;
  const collectorApiKey = envObj.COLLECTOR_API_KEY || envObj.COLLECTOR_INGEST_API_KEY;

  if (!isDevOrTest) {
    // 1. Validate JWT_SECRET in production
    if (!jwtSecret || typeof jwtSecret !== 'string' || !jwtSecret.trim()) {
      throw new Error('Configuration error: JWT_SECRET must be explicitly configured in production.');
    }
    jwtSecret = jwtSecret.trim();
    if (INSECURE_SECRETS.has(jwtSecret.toLowerCase())) {
      throw new Error('Configuration error: Insecure or placeholder JWT_SECRET is rejected in production.');
    }
    if (jwtSecret.length < 32) {
      throw new Error('Configuration error: JWT_SECRET is insufficiently strong (minimum 32 characters required in production).');
    }

    // 2. Validate TOKEN_HMAC_SECRET in production
    if (!tokenHmacSecret || typeof tokenHmacSecret !== 'string' || !tokenHmacSecret.trim()) {
      throw new Error('Configuration error: TOKEN_HMAC_SECRET must be explicitly configured in production.');
    }
    tokenHmacSecret = tokenHmacSecret.trim();
    if (INSECURE_SECRETS.has(tokenHmacSecret.toLowerCase())) {
      throw new Error('Configuration error: Insecure or placeholder TOKEN_HMAC_SECRET is rejected in production.');
    }
    if (tokenHmacSecret.length < 32) {
      throw new Error('Configuration error: TOKEN_HMAC_SECRET is insufficiently strong (minimum 32 characters required in production).');
    }

    // 3. Validate CORS_ALLOWED_ORIGINS in production
    if (!rawCors || typeof rawCors !== 'string' || !rawCors.trim()) {
      throw new Error('Configuration error: CORS_ALLOWED_ORIGINS must be explicitly configured in production.');
    }
    const parsedOrigins = parseCorsOrigins(rawCors);
    if (parsedOrigins.length === 0) {
      throw new Error('Configuration error: CORS_ALLOWED_ORIGINS must contain at least one trusted origin.');
    }
    for (const origin of parsedOrigins) {
      if (origin === '*') {
        throw new Error('Configuration error: Wildcard CORS origins are forbidden in production.');
      }
      if (!isValidOrigin(origin)) {
        throw new Error(
          `Configuration error: Malformed CORS origin '${origin}'. Origins must be valid http/https URLs without path or query.`
        );
      }
    }

    // 4. Validate COLLECTOR_API_KEY in production if set
    if (collectorApiKey) {
      const trimmedKey = collectorApiKey.trim();
      if (INSECURE_SECRETS.has(trimmedKey.toLowerCase())) {
        throw new Error('Configuration error: Insecure or published default COLLECTOR_API_KEY is rejected in production.');
      }
      if (trimmedKey.length < 16) {
        throw new Error('Configuration error: COLLECTOR_API_KEY is insufficiently strong (minimum 16 characters required in production).');
      }
    }
  } else {
    // Safe fallbacks only when development/test mode is explicitly enabled
    if (!jwtSecret || !jwtSecret.trim()) {
      jwtSecret = 'dev_only_jwt_secret_do_not_use_in_production_32chars';
    }
    if (!tokenHmacSecret || !tokenHmacSecret.trim()) {
      tokenHmacSecret = 'dev_only_hmac_secret_do_not_use_in_production_32chars';
    }
  }

  // Parse CORS origins
  let corsAllowedOrigins = [];
  if (rawCors) {
    corsAllowedOrigins = parseCorsOrigins(rawCors);
    if (isDevOrTest) {
      for (const origin of corsAllowedOrigins) {
        if (origin !== '*' && !isValidOrigin(origin)) {
          throw new Error(`Configuration error: Malformed CORS origin '${origin}'.`);
        }
      }
    }
  } else if (isDevOrTest) {
    corsAllowedOrigins = [
      'http://localhost:3000',
      'http://127.0.0.1:3000',
      'http://localhost:5000',
      'http://127.0.0.1:5000',
    ];
  }

  return {
    port: parseInt(envObj.PORT, 10) || 3000,
    jwtSecret,
    tokenHmacSecret,
    jwtExpiresIn: '15m',
    corsAllowedOrigins: corsAllowedOrigins.map(o => o.replace(/\/$/, '')),
    collectorUrl: envObj.COLLECTOR_URL || 'http://127.0.0.1:5000/events',
    collectorApiKey: collectorApiKey ? collectorApiKey.trim() : null,
    isDevOrTest,
    mode,
  };
}

// Initial configuration evaluated at module load
const resolvedConfig = validateConfig(process.env);

const config = {
  ...resolvedConfig,
  validateConfig,
  getEnvironmentMode,
  isValidOrigin,
  parseCorsOrigins,
};

module.exports = config;
