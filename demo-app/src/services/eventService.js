/**
 * A simple abstraction for TokenLine event integration.
 * Since the official schema/event.schema.json does not exist yet,
 * this acts as the interface.
 * 
 * It ensures we log safe metadata and never log raw tokens or passwords.
 */

function emit(eventName, payload) {
  const event = {
    eventType: eventName,
    timestamp: new Date().toISOString(),
    ...payload,
  };

  // Check that raw token fields are not being emitted
  if (event.rawRefreshToken || event.rawAccessToken || event.password) {
    console.warn('[SECURITY WARNING] Attempted to emit raw sensitive data in event. Stripping data.');
    delete event.rawRefreshToken;
    delete event.rawAccessToken;
    delete event.password;
  }

  // In a real integration, this might send the event to a message broker or the TokenLine collector API
  // For the local demo, we just log the abstract event structure
  console.log(`[EVENT] ${eventName}:`, JSON.stringify(event));
}

module.exports = {
  emit,
};
