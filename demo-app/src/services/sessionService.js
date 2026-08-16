const { generateOpaqueToken } = require('../utils/tokenId');

// In-memory session store for the demo
// Map<sessionId, SessionObject>
const sessions = new Map();

function createSession(userId, deviceInfo) {
  const sessionId = generateOpaqueToken(16);
  
  const session = {
    sessionId,
    userId,
    deviceId: deviceInfo.deviceId || 'unknown',
    deviceName: deviceInfo.deviceName || 'unknown',
    userAgent: deviceInfo.userAgent || 'unknown',
    ipAddress: deviceInfo.ipAddress || '127.0.0.1',
    createdAt: new Date().toISOString(),
    lastActivityAt: new Date().toISOString(),
    revoked: false,
  };
  
  sessions.set(sessionId, session);
  return session;
}

function getSession(sessionId) {
  return sessions.get(sessionId);
}

function revokeSession(sessionId) {
  const session = sessions.get(sessionId);
  if (session) {
    session.revoked = true;
    session.lastActivityAt = new Date().toISOString();
  }
  return session;
}

function updateActivity(sessionId) {
  const session = sessions.get(sessionId);
  if (session && !session.revoked) {
    session.lastActivityAt = new Date().toISOString();
  }
}

module.exports = {
  createSession,
  getSession,
  revokeSession,
  updateActivity,
};
