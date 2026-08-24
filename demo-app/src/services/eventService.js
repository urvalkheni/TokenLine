/**
 * A simple abstraction for TokenLine event integration.
 * Maps internal events to the canonical schema/event.schema.json format
 * and emits them to the Python Event Collector service.
 */
const crypto = require('crypto');

function emit(eventName, payload) {
  // Safe console logging
  const eventLog = {
    eventType: eventName,
    timestamp: new Date().toISOString(),
    ...payload,
  };
  
  if (eventLog.rawRefreshToken || eventLog.rawAccessToken || eventLog.password) {
    console.warn('[SECURITY WARNING] Attempted to emit raw sensitive data in event. Stripping data.');
    delete eventLog.rawRefreshToken;
    delete eventLog.rawAccessToken;
    delete eventLog.password;
  }
  console.log(`[EVENT] ${eventName}:`, JSON.stringify(eventLog));

  // List of event types supported by TokenLine's JSON Schema
  const supportedEvents = [
    "token_issued",
    "token_used",
    "token_refreshed",
    "token_revoked",
    "token_expired",
    "logout",
    "refresh_reuse_detected",
    "suspicious_location",
    "suspicious_device",
    "replay_detected"
  ];

  // Map internal event names to event.schema.json event_type enums
  let mappedEventType = eventName;
  if (eventName === 'login') {
    mappedEventType = 'token_issued';
  } else if (eventName === 'login_failed' || eventName === 'token_refresh_failed') {
    mappedEventType = 'replay_detected';
  }

  if (!supportedEvents.includes(mappedEventType)) {
    return; // Don't send unsupported events
  }

  // Generate unique event_id
  const event_id = 'evt-' + crypto.randomUUID().slice(0, 8);

  // Extract IP and UA context from payload or set defaults
  const ip = payload.deviceInfo?.ip || '127.0.0.1';
  const ua = payload.deviceInfo?.userAgent || 'Mozilla/5.0';

  // Compute privacy-preserving hashes
  const ip_hash = crypto.createHash('sha256').update(ip).digest('hex').slice(0, 16);
  const user_agent_family = ua.split('/')[0] || 'Unknown';

  // Determine token hash and parent token hash
  let token_hash = payload.tokenIdentifier || 'root-token';
  let parent_token_hash = payload.parentIdentifier || null;
  let token_family = payload.tokenFamilyId || 'family-unknown';

  if (mappedEventType === 'refresh_reuse_detected') {
    token_hash = payload.reusedTokenIdentifier || 'reused-token';
  } else if (mappedEventType === 'token_refreshed') {
    token_hash = payload.successorIdentifier || 'successor-token';
    parent_token_hash = payload.parentIdentifier || null;
  }

  // Construct canonical payload matching schema/event.schema.json
  const canonicalPayload = {
    event_id: event_id,
    event_type: mappedEventType,
    time: new Date().toISOString(),
    user_id: String(payload.userId || 'demo-user'),
    token_hash: token_hash,
    token_family: token_family,
    parent_token_hash: parent_token_hash,
    ip_hash: ip_hash,
    country: 'IN',
    device_id: payload.sessionId || 'session-default',
    user_agent_family: user_agent_family,
    endpoint: payload.endpoint || '/auth/login',
    result: (eventName.includes('failed') || eventName.includes('reuse')) ? 'rejected' : 'accepted'
  };

  // Send the event to the Event Collector API
  const collectorUrl = 'http://localhost:5000/events';
  fetch(collectorUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(canonicalPayload)
  })
  .then(res => {
    if (!res.ok) {
      res.text().then(text => console.error(`[COLLECTOR ERROR] Ingestion failed: ${res.status} - ${text}`));
    } else {
      console.log(`[COLLECTOR] Emitted event ${mappedEventType} (${event_id}) successfully integrated.`);
    }
  })
  .catch(err => {
    // Fail silently in the background if the Python collector is offline
    console.warn(`[COLLECTOR WARNING] Failed to connect to Event Collector at ${collectorUrl}: ${err.message}`);
  });
}

module.exports = {
  emit,
};
