const config = require('../config');

/**
 * Express middleware to enforce restricted CORS based on an explicit allowlist.
 * Allows only explicitly configured frontend origins in production.
 * Supports preflight OPTIONS requests with required methods and headers.
 */
function corsMiddleware(req, res, next) {
  const origin = req.headers.origin;
  const allowedOrigins = config.corsAllowedOrigins || [];

  const isAllowed = Boolean(
    origin && (
      allowedOrigins.includes(origin) ||
      allowedOrigins.includes(origin.replace(/\/$/, '')) ||
      (config.isDevOrTest && allowedOrigins.includes('*'))
    )
  );

  if (isAllowed) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader(
      'Access-Control-Allow-Headers',
      'Content-Type, Authorization, X-API-Key, X-Request-ID, X-Correlation-ID'
    );
    res.setHeader('Access-Control-Max-Age', '86400');
    res.setHeader('Vary', 'Origin');
  }

  if (req.method === 'OPTIONS') {
    if (origin) {
      if (isAllowed) {
        return res.sendStatus(204);
      }
      return res.status(403).json({ error: 'CORS origin not allowed' });
    }
    // Preflight without Origin header
    return res.sendStatus(204);
  }

  next();
}

module.exports = {
  corsMiddleware,
};
