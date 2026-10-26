const crypto = require('crypto');
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const config = require('../config');
const { users } = require('../../data/users');
const { generateId, hashToken } = require('../utils/tokenId');
const { createSession, getSession, revokeSession } = require('../services/sessionService');
const { issueRefreshToken, findToken, invalidateToken, setSuccessor, revokeFamily } = require('../services/tokenService');
const eventService = require('../services/eventService');
const { requireAuth } = require('../middleware/auth');

const router = express.Router();

function generateAccessToken(userId, sessionId, tokenFamilyId) {
  return jwt.sign(
    {
      jti: generateId(), // Ensure uniqueness even if generated in the same millisecond
      sub: userId,
      sessionId,
      tokenFamilyId,
      tokenType: 'access',
    },
    config.jwtSecret,
    { expiresIn: config.jwtExpiresIn }
  );
}

function extractDeviceInfo(req) {
  return {
    userAgent: req.get('User-Agent') || null,
    ipAddress: req.ip || req.socket?.remoteAddress || null,
    deviceId: req.body?.deviceId || req.get('X-Device-ID') || null,
    deviceName: req.body?.deviceName || null,
  };
}

router.post('/login', (req, res) => {
  const { username, password } = req.body;
  const deviceInfo = extractDeviceInfo(req);
  const endpoint = req.originalUrl || req.path;

  const user = users.find(u => u.username === username);
  if (!user || !bcrypt.compareSync(password, user.passwordHash)) {
    eventService.emit('login_failed', {
      username: username || 'unknown',
      userId: user ? user.id : (username || 'unknown'),
      deviceInfo,
      deviceId: deviceInfo.deviceId || (deviceInfo.userAgent ? 'dev-' + crypto.createHash('sha256').update(deviceInfo.userAgent + (deviceInfo.ipAddress || '')).digest('hex').slice(0, 12) : 'dev-unauthenticated'),
      endpoint
    });
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  const session = createSession(user.id, deviceInfo);
  const tokenFamilyId = generateId();

  // Issue tokens
  const { rawToken: refreshToken, hashedToken } = issueRefreshToken(user.id, session.sessionId, tokenFamilyId);
  const accessToken = generateAccessToken(user.id, session.sessionId, tokenFamilyId);

  eventService.emit('token_issued', {
    userId: user.id,
    sessionId: session.sessionId,
    deviceId: deviceInfo.deviceId || session.sessionId,
    tokenFamilyId,
    tokenType: 'refresh_token',
    tokenIdentifier: hashedToken,
    deviceInfo,
    endpoint
  });

  // DO NOT return password or sensitive data. Do NOT log raw tokens.
  return res.json({
    accessToken,
    refreshToken,
    sessionId: session.sessionId
  });
});

router.post('/refresh', (req, res) => {
  const { refreshToken } = req.body;
  const deviceInfo = extractDeviceInfo(req);
  const endpoint = req.originalUrl || req.path;
  
  if (!refreshToken) {
    return res.status(400).json({ error: 'Refresh token required' });
  }

  const hashedToken = hashToken(refreshToken);
  const tokenObj = findToken(hashedToken);

  if (!tokenObj) {
    eventService.emit('token_refresh_failed', {
      reason: 'token_not_found',
      tokenIdentifier: hashedToken,
      userId: 'unknown',
      deviceId: deviceInfo.deviceId || 'unregistered-device',
      deviceInfo,
      endpoint
    });
    return res.status(401).json({ error: 'Invalid refresh token' });
  }

  const session = getSession(tokenObj.sessionId);
  if (!session || session.revoked) {
    eventService.emit('token_refresh_failed', {
      reason: 'session_revoked',
      tokenIdentifier: hashedToken,
      sessionId: tokenObj.sessionId,
      deviceId: deviceInfo.deviceId || tokenObj.sessionId,
      userId: tokenObj.userId,
      tokenFamilyId: tokenObj.tokenFamilyId,
      deviceInfo,
      endpoint
    });
    return res.status(401).json({ error: 'Session revoked or invalid' });
  }

  // Check if token has already been rotated (refresh token reuse)
  if (!tokenObj.valid) {
    // This is a critical security event: an old refresh token was used!
    eventService.emit('refresh_reuse_detected', {
      userId: tokenObj.userId,
      sessionId: tokenObj.sessionId,
      deviceId: deviceInfo.deviceId || tokenObj.sessionId,
      tokenFamilyId: tokenObj.tokenFamilyId,
      reusedTokenIdentifier: hashedToken,
      deviceInfo,
      endpoint
    });

    // Revoke entire token family and session to protect the user
    revokeFamily(tokenObj.tokenFamilyId);
    revokeSession(tokenObj.sessionId);
    
    return res.status(401).json({ error: 'Invalid refresh token. Session has been revoked due to suspicious activity.' });
  }

  // Valid refresh! Invalidate old token.
  invalidateToken(hashedToken);

  // Issue new tokens
  const { rawToken: newRefreshToken, hashedToken: newHashedToken } = issueRefreshToken(
    tokenObj.userId, 
    tokenObj.sessionId, 
    tokenObj.tokenFamilyId, 
    hashedToken
  );
  
  setSuccessor(hashedToken, newHashedToken);
  
  const newAccessToken = generateAccessToken(tokenObj.userId, tokenObj.sessionId, tokenObj.tokenFamilyId);

  eventService.emit('token_refreshed', {
    userId: tokenObj.userId,
    sessionId: tokenObj.sessionId,
    deviceId: deviceInfo.deviceId || tokenObj.sessionId,
    tokenFamilyId: tokenObj.tokenFamilyId,
    parentIdentifier: hashedToken,
    successorIdentifier: newHashedToken,
    deviceInfo,
    endpoint
  });

  return res.json({
    accessToken: newAccessToken,
    refreshToken: newRefreshToken,
    sessionId: tokenObj.sessionId
  });
});

router.post('/logout', requireAuth, (req, res) => {
  const { sessionId, userId, tokenFamilyId } = req.user;
  const deviceInfo = extractDeviceInfo(req);
  
  revokeSession(sessionId);
  
  eventService.emit('logout', {
    userId,
    sessionId,
    deviceId: deviceInfo.deviceId || sessionId,
    tokenFamilyId,
    deviceInfo,
    endpoint: req.originalUrl || req.path
  });

  res.json({ message: 'Logged out successfully' });
});

module.exports = router;
