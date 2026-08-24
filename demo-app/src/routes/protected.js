const express = require('express');
const { requireAuth } = require('../middleware/auth');
const eventService = require('../services/eventService');
const { users } = require('../../data/users');

const router = express.Router();

router.get('/profile', requireAuth, (req, res) => {
  const { userId, sessionId, tokenFamilyId } = req.user;

  // Emit an event that the token was successfully used
  eventService.emit('token_used', {
    userId,
    sessionId,
    tokenFamilyId,
    endpoint: '/api/profile'
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
