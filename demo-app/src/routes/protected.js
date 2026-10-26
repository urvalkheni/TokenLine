const express = require('express');
const { requireAuth } = require('../middleware/auth');
const eventService = require('../services/eventService');
const { users } = require('../../data/users');

const router = express.Router();

router.get('/profile', requireAuth, (req, res) => {
  const { userId, sessionId, tokenFamilyId } = req.user;

  const deviceInfo = {
    userAgent: req.get('User-Agent') || null,
    ipAddress: req.ip || req.socket?.remoteAddress || null,
    deviceId: req.body?.deviceId || req.get('X-Device-ID') || null,
  };

  // Emit an event that the token was successfully used
  eventService.emit('token_used', {
    userId,
    sessionId,
    deviceId: deviceInfo.deviceId || sessionId,
    tokenFamilyId,
    deviceInfo,
    endpoint: req.originalUrl || req.path || '/api/profile'
  });

  const user = users.find(u => u.id === userId);
  
  res.json({
    message: 'Profile data retrieved successfully',
    user: {
      id: user.id,
      username: user.username,
    },
    sessionInfo: {
      sessionId,
      tokenFamilyId
    }
  });
});

module.exports = router;
