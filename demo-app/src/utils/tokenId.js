const crypto = require('crypto');
const config = require('../config');

/**
 * Generate a cryptographically secure random opaque token.
 * Used for refresh tokens and session identifiers.
 */
function generateOpaqueToken(byteLength = 32) {
  return crypto.randomBytes(byteLength).toString('base64url');
}

/**
 * Compute a privacy-preserving identifier for a token.
 * Used so raw refresh tokens do not need to be stored or logged.
 */
function hashToken(rawToken) {
  return crypto.createHmac('sha256', config.jwtSecret)
    .update(rawToken)
    .digest('hex');
}

/**
 * Generate a cryptographically secure random ID (e.g., for token family IDs).
 */
function generateId() {
  return crypto.randomUUID();
}

module.exports = {
  generateOpaqueToken,
  hashToken,
  generateId,
};
