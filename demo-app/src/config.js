require('dotenv').config();

module.exports = {
  port: process.env.PORT || 3000,
  jwtSecret: process.env.JWT_SECRET || 'fallback_local_secret_do_not_use_in_prod',
  tokenHmacSecret: process.env.TOKEN_HMAC_SECRET || 'fallback_hmac_secret_do_not_use_in_prod',
  jwtExpiresIn: '15m', // Short expiration for demo purposes
};
