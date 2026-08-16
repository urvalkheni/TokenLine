const { generateOpaqueToken, hashToken, generateId } = require('../utils/tokenId');

// In-memory token store for the demo
// Map<hashedToken, TokenObject>
const refreshTokens = new Map();

function issueRefreshToken(userId, sessionId, tokenFamilyId, parentHashedToken = null) {
  const rawToken = generateOpaqueToken();
  const hashedToken = hashToken(rawToken);

  const tokenObj = {
    hashedToken,
    userId,
    sessionId,
    tokenFamilyId,
    parentHashedToken,
    successorHashedToken: null,
    issuedAt: new Date().toISOString(),
    valid: true,
  };

  refreshTokens.set(hashedToken, tokenObj);

  return { rawToken, hashedToken, tokenObj };
}

function findToken(hashedToken) {
  return refreshTokens.get(hashedToken);
}

function invalidateToken(hashedToken) {
  const token = refreshTokens.get(hashedToken);
  if (token) {
    token.valid = false;
  }
}

function setSuccessor(parentHashedToken, successorHashedToken) {
  const parentToken = refreshTokens.get(parentHashedToken);
  if (parentToken) {
    parentToken.successorHashedToken = successorHashedToken;
  }
}

function revokeFamily(tokenFamilyId) {
  for (const token of refreshTokens.values()) {
    if (token.tokenFamilyId === tokenFamilyId) {
      token.valid = false;
    }
  }
}

module.exports = {
  issueRefreshToken,
  findToken,
  invalidateToken,
  setSuccessor,
  revokeFamily,
};
