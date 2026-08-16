const jwt = require('jsonwebtoken');
const config = require('../config');
const { getSession, updateActivity } = require('../services/sessionService');

function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Missing or invalid authorization header' });
  }

  // Extract the token (do not log this!)
  const token = authHeader.split(' ')[1];

  try {
    const payload = jwt.verify(token, config.jwtSecret);
    
    // Check if session exists and is valid
    const session = getSession(payload.sessionId);
    if (!session) {
      return res.status(401).json({ error: 'Session not found' });
    }
    
    if (session.revoked) {
      return res.status(401).json({ error: 'Session has been revoked' });
    }

    // Update session activity
    updateActivity(session.sessionId);

    // Attach minimal claims to request
    req.user = {
      userId: payload.sub,
      sessionId: payload.sessionId,
      tokenFamilyId: payload.tokenFamilyId,
    };
    
    next();
  } catch (err) {
    // JWT verification failed (expired, malformed, etc.)
    return res.status(401).json({ error: 'Invalid or expired access token' });
  }
}

module.exports = {
  requireAuth,
};
