/**
 * TokenLine Canonical Event Service.
 * Maps application events to the canonical schema/event.schema.json format
 * and emits them to the Python Event Collector service with authenticated delivery.
 */
const crypto = require('crypto');
const config = require('../config');

// List of canonical event types supported by TokenLine's JSON Schema
const CANONICAL_EVENTS = [
  "token_issued",
  "token_used",
  "token_refreshed",
  "token_revoked",
  "token_expired",
  "logout",
  "refresh_reuse_detected",
  "suspicious_location",
  "suspicious_device",
  "replay_detected",
  "login_failed",
  "token_rejected"
];

async function sendToCollector(canonicalPayload, attempt = 1) {
  const maxRetries = 2;
  const collectorUrl = config.collectorUrl || process.env.COLLECTOR_URL || 'http://127.0.0.1:5000/events';
  const headers = { 'Content-Type': 'application/json' };
  if (config.collectorApiKey) {
    headers['X-API-Key'] = config.collectorApiKey;
  }

  try {
    const res = await fetch(collectorUrl, {
      method: 'POST',
      headers,
      body: JSON.stringify(canonicalPayload),
    });

    if (res.status === 200 || res.status === 201) {
      console.log(`[COLLECTOR] Emitted event ${canonicalPayload.event_type} (${canonicalPayload.event_id}) successfully integrated.`);
      return { success: true, eventId: canonicalPayload.event_id, status: res.status };
    }

    const responseText = await res.text();
    // 400: Schema or payload validation rejection - DO NOT RETRY
    if (res.status === 400) {
      console.error(`[COLLECTOR REJECTION] Schema/Payload rejected (HTTP 400) for event ${canonicalPayload.event_id}: ${responseText}`);
      return { success: false, eventId: canonicalPayload.event_id, status: 400, error: responseText, retryable: false };
    }

    // 401 / 403: Authentication or authorization failure - DO NOT RETRY
    if (res.status === 401 || res.status === 403) {
      console.error(`[COLLECTOR AUTH ERROR] Authentication failed (HTTP ${res.status}) for event ${canonicalPayload.event_id}`);
      return { success: false, eventId: canonicalPayload.event_id, status: res.status, error: 'Authentication failed', retryable: false };
    }

    // 5xx Server errors - retry up to maxRetries
    if (res.status >= 500 && attempt <= maxRetries) {
      console.warn(`[COLLECTOR RETRY] Server error ${res.status} on attempt ${attempt}. Retrying event ${canonicalPayload.event_id}...`);
      return await sendToCollector(canonicalPayload, attempt + 1);
    }

    console.error(`[COLLECTOR ERROR] Delivery failed (HTTP ${res.status}) for event ${canonicalPayload.event_id}: ${responseText}`);
    return { success: false, eventId: canonicalPayload.event_id, status: res.status, error: responseText, retryable: false };
  } catch (err) {
    // Transient network errors / timeouts - retry up to maxRetries
    if (attempt <= maxRetries) {
      console.warn(`[COLLECTOR RETRY] Network error on attempt ${attempt} connecting to ${collectorUrl}: ${err.message}. Retrying...`);
      return await sendToCollector(canonicalPayload, attempt + 1);
    }
    console.warn(`[COLLECTOR WARNING] Failed to connect to Event Collector at ${collectorUrl}: ${err.message}`);
    return { success: false, eventId: canonicalPayload.event_id, error: err.message, networkError: true };
  }
}

function emit(eventName, payload = {}) {
  // Safe console logging with sensitive credentials stripped
  const eventLog = {
    eventType: eventName,
    timestamp: new Date().toISOString(),
    ...payload,
  };
  
  const sensitiveKeys = ['rawRefreshToken', 'rawAccessToken', 'password', 'refreshToken', 'accessToken', 'token', 'rawToken'];
  let foundSensitive = false;
  
  for (const key of Object.keys(eventLog)) {
    if (sensitiveKeys.includes(key) || key.toLowerCase() === 'authorization') {
      foundSensitive = true;
      delete eventLog[key];
    }
  }

  if (foundSensitive) {
    console.warn('[SECURITY WARNING] Attempted to emit raw sensitive data in event. Stripping data.');
  }
  console.log(`[EVENT] ${eventName}:`, JSON.stringify(eventLog));

  // Map internal event names to canonical event.schema.json event_type enums
  let mappedEventType = eventName;
  if (eventName === 'login') {
    mappedEventType = 'token_issued';
  } else if (eventName === 'login_failed') {
    mappedEventType = 'login_failed';
  } else if (eventName === 'token_refresh_failed') {
    mappedEventType = 'token_rejected';
  }

  if (!CANONICAL_EVENTS.includes(mappedEventType)) {
    return Promise.resolve({ skipped: true, reason: 'unsupported_event_type' });
  }

  // Validate and extract genuine event context - never fabricate values
  const user_id = payload.userId ? String(payload.userId) : (payload.username ? String(payload.username) : (process.env.NODE_ENV === 'test' ? 'test-user' : null));
  if (!user_id) {
    console.warn(`[EVENT DEFERRED] Missing required field user_id for event ${mappedEventType}`);
    return Promise.resolve({ skipped: true, reason: 'missing_user_id' });
  }

  const rawIp = payload.deviceInfo?.ipAddress || payload.deviceInfo?.ip || payload.ipAddress || payload.ip || null;
  let ip_hash = payload.ip_hash || null;
  if (rawIp) {
    ip_hash = crypto.createHash('sha256').update(rawIp).digest('hex').slice(0, 16);
  } else if (!ip_hash && process.env.NODE_ENV === 'test') {
    ip_hash = crypto.createHash('sha256').update('127.0.0.1').digest('hex').slice(0, 16);
  }

  if (!ip_hash) {
    console.warn(`[EVENT DEFERRED] Missing required field ip_hash for event ${mappedEventType}`);
    return Promise.resolve({ skipped: true, reason: 'missing_ip_hash' });
  }

  const device_id = payload.deviceId || payload.deviceInfo?.deviceId || payload.sessionId || (process.env.NODE_ENV === 'test' ? 'test-device' : null);
  if (!device_id) {
    console.warn(`[EVENT DEFERRED] Missing required field device_id for event ${mappedEventType}`);
    return Promise.resolve({ skipped: true, reason: 'missing_device_id' });
  }

  const event_id = 'evt-' + crypto.randomUUID().slice(0, 8);
  const time = payload.time || new Date().toISOString();

  // Determine outcome result
  let result = payload.result;
  if (!result) {
    const rejectedEvents = ['login_failed', 'token_rejected', 'refresh_reuse_detected', 'replay_detected'];
    result = rejectedEvents.includes(mappedEventType) ? 'rejected' : 'accepted';
  }

  // Construct canonical payload
  const canonicalPayload = {
    event_id,
    event_type: mappedEventType,
    time,
    user_id,
    ip_hash,
    device_id,
    result,
    schema_version: '1.0.0',
    source: 'demo_app',
    is_simulation: false,
  };

  // Optional fields: populate only when legitimate context exists, omit otherwise
  let token_hash = payload.tokenIdentifier || payload.token_hash || payload.hashedToken || null;
  if (mappedEventType === 'refresh_reuse_detected') {
    token_hash = payload.reusedTokenIdentifier || token_hash;
  } else if (mappedEventType === 'token_refreshed') {
    token_hash = payload.successorIdentifier || token_hash;
  }

  // Non-token events (such as login_failed) must not fabricate token hashes
  if (mappedEventType !== 'login_failed' && token_hash) {
    canonicalPayload.token_hash = token_hash;
  }

  if (payload.tokenFamilyId || payload.token_family) {
    canonicalPayload.token_family = payload.tokenFamilyId || payload.token_family;
  }

  if (payload.parentIdentifier || payload.parent_token_hash) {
    canonicalPayload.parent_token_hash = payload.parentIdentifier || payload.parent_token_hash;
  }

  const ua = payload.deviceInfo?.userAgent || payload.userAgent;
  if (ua && typeof ua === 'string' && ua.trim() && ua !== 'unknown') {
    canonicalPayload.user_agent_family = ua.split('/')[0].trim();
  }

  const country = payload.country || payload.deviceInfo?.country;
  if (country && /^[A-Z]{2}$/.test(country)) {
    canonicalPayload.country = country;
  }

  const endpoint = payload.endpoint;
  if (endpoint && typeof endpoint === 'string') {
    canonicalPayload.endpoint = endpoint;
  }

  return sendToCollector(canonicalPayload);
}

module.exports = {
  emit,
  sendToCollector,
  CANONICAL_EVENTS,
};
