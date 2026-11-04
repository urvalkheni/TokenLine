/** TokenLine dashboard with explicit live collector and demo data modes. */

// --- MOCK DATABASE DATASETS ---
const MOCK_EVENTS = [
  {
    "event_id": "evt-001",
    "event_type": "token_issued",
    "time": "2026-08-16T10:00:00Z",
    "user_id": "user-khushi",
    "token_hash": "tok_a1b2c3d4e5f6",
    "token_family": "fam-khushi-session-1",
    "parent_token_hash": null,
    "ip_hash": "ip_a8e9f2b1",
    "country": "IN",
    "device_id": "device-laptop-khushi",
    "user_agent_family": "Chrome",
    "endpoint": "/api/auth/login",
    "result": "accepted"
  },
  {
    "event_id": "evt-002",
    "event_type": "token_used",
    "time": "2026-08-16T10:05:00Z",
    "user_id": "user-khushi",
    "token_hash": "tok_a1b2c3d4e5f6",
    "token_family": "fam-khushi-session-1",
    "parent_token_hash": null,
    "ip_hash": "ip_a8e9f2b1",
    "country": "IN",
    "device_id": "device-laptop-khushi",
    "user_agent_family": "Chrome",
    "endpoint": "/api/v1/profile",
    "result": "accepted"
  },
  {
    "event_id": "evt-003",
    "event_type": "token_refreshed",
    "time": "2026-08-16T10:30:00Z",
    "user_id": "user-khushi",
    "token_hash": "tok_f5g6h7j8k9l0",
    "token_family": "fam-khushi-session-1",
    "parent_token_hash": "tok_a1b2c3d4e5f6",
    "ip_hash": "ip_a8e9f2b1",
    "country": "IN",
    "device_id": "device-laptop-khushi",
    "user_agent_family": "Chrome",
    "endpoint": "/api/auth/refresh",
    "result": "accepted"
  },
  {
    "event_id": "evt-004",
    "event_type": "token_used",
    "time": "2026-08-16T10:35:00Z",
    "user_id": "user-khushi",
    "token_hash": "tok_f5g6h7j8k9l0",
    "token_family": "fam-khushi-session-1",
    "parent_token_hash": "tok_a1b2c3d4e5f6",
    "ip_hash": "ip_a8e9f2b1",
    "country": "IN",
    "device_id": "device-laptop-khushi",
    "user_agent_family": "Chrome",
    "endpoint": "/api/v1/dashboard",
    "result": "accepted"
  },
  {
    "event_id": "evt-005",
    "event_type": "refresh_reuse_detected",
    "time": "2026-08-16T10:40:00Z",
    "user_id": "user-khushi",
    "token_hash": "tok_a1b2c3d4e5f6",
    "token_family": "fam-khushi-session-1",
    "parent_token_hash": null,
    "ip_hash": "ip_d9c8b7a6",
    "country": "US",
    "device_id": "device-unknown-attacker",
    "user_agent_family": "Python-requests",
    "endpoint": "/api/auth/refresh",
    "result": "rejected"
  },
  {
    "event_id": "evt-006",
    "event_type": "token_expired",
    "time": "2026-08-16T11:00:00Z",
    "user_id": "user-khushi",
    "token_hash": "tok_f5g6h7j8k9l0",
    "token_family": "fam-khushi-session-1",
    "parent_token_hash": "tok_a1b2c3d4e5f6",
    "ip_hash": "ip_a8e9f2b1",
    "country": "IN",
    "device_id": "device-laptop-khushi",
    "user_agent_family": "Chrome",
    "endpoint": "/api/v1/dashboard",
    "result": "rejected"
  },
  {
    "event_id": "evt-007",
    "event_type": "token_issued",
    "time": "2026-08-16T12:00:00Z",
    "user_id": "user-reeva",
    "token_hash": "tok_z9y8x7w6v5u4",
    "token_family": "fam-reeva-session-2",
    "parent_token_hash": null,
    "ip_hash": "ip_e3f4a1b2",
    "country": "US",
    "device_id": "device-phone-reeva",
    "user_agent_family": "MobileSafari",
    "endpoint": "/api/auth/login",
    "result": "accepted"
  },
  {
    "event_id": "evt-008",
    "event_type": "suspicious_location",
    "time": "2026-08-16T12:05:00Z",
    "user_id": "user-reeva",
    "token_hash": "tok_z9y8x7w6v5u4",
    "token_family": "fam-reeva-session-2",
    "parent_token_hash": null,
    "ip_hash": "ip_f9f9f9f9",
    "country": "NL",
    "device_id": "device-unknown-proxy",
    "user_agent_family": "Firefox",
    "endpoint": "/api/v1/profile",
    "result": "accepted"
  }
];

// --- APP STATE ---
let activeTab = 'dashboard';
let eventsList = [];
let selectedTimelineEvent = null;
let dataMode = sessionStorage.getItem('tokenline.dataMode') || 'live';

// --- DOM ELEMENT REFERENCES ---
const navItems = document.querySelectorAll('.nav-item');
const tabViews = document.querySelectorAll('.tab-view');
const eventFeedTable = document.getElementById('dashboard-event-feed');
const tokenSearchInput = document.getElementById('token-search');

// --- APP INITIALIZATION ---
document.addEventListener('DOMContentLoaded', () => {
  setupNavigation();
  setupSearch();
  setupDataSettings();
  loadDashboardData();
  setupAlertsView();
});

// --- NAVIGATION & ROUTING ---
function setupNavigation() {
  navItems.forEach(item => {
    item.addEventListener('click', () => {
      const targetTab = item.getAttribute('data-tab');
      switchTab(targetTab);
    });
  });
}

function switchTab(tabName) {
  activeTab = tabName;
  
  // Update sidebar classes
  navItems.forEach(item => {
    if (item.getAttribute('data-tab') === tabName) {
      item.classList.add('active');
    } else {
      item.classList.remove('active');
    }
  });

  // Update visible view container
  tabViews.forEach(view => {
    if (view.id === `view-${tabName}`) {
      view.classList.add('active');
    } else {
      view.classList.remove('active');
    }
  });

  // Trigger tab-specific load actions
  if (tabName === 'dashboard') {
    loadDashboardData();
  } else if (tabName === 'timeline') {
    // Default to the first token chain if none is selected yet
    if (eventsList.length > 0) {
      renderTimelineForToken(eventsList[0].token_hash);
    }
  } else if (tabName === 'alerts') {
    renderAlerts();
  }
}

// --- CORE UTILITY FUNCTIONS ---
function maskToken(hash) {
  if (!hash) return 'N/A';
  if (hash.length <= 10) return hash;
  return `${hash.slice(0, 7)}...${hash.slice(-5)}`;
}

function formatDate(isoString) {
  const date = new Date(isoString);
  return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }) + ` (${date.toLocaleDateString()})`;
}

function setCollectorStatus(label, state) {
  const status = document.getElementById('collector-status');
  const dot = status?.querySelector('.status-dot');
  if (!status || !dot) return;
  dot.className = `status-dot ${state}`;
  status.lastChild.textContent = ` ${label}`;
  const indicator = document.getElementById('live-indicator');
  if (indicator) {
    indicator.textContent = dataMode === 'demo'
      ? 'DEMO DATA'
      : state === 'healthy'
        ? 'LIVE'
        : state === 'loading'
          ? 'LOADING'
          : state === 'auth'
            ? 'AUTH REQUIRED'
            : 'UNAVAILABLE';
    indicator.className = state === 'error' || state === 'auth' ? 'badge offline' : 'badge';
  }
}

function showTableMessage(message, table = eventFeedTable) {
  if (!table) return;
  table.textContent = '';
  if (table.tagName !== 'TBODY') {
    const paragraph = document.createElement('p');
    paragraph.className = 'table-message';
    paragraph.textContent = message;
    table.appendChild(paragraph);
    return;
  }
  const row = document.createElement('tr');
  const cell = document.createElement('td');
  cell.colSpan = 6;
  cell.className = 'table-message';
  cell.textContent = message;
  row.appendChild(cell);
  table.appendChild(row);
}

async function getEvents() {
  if (dataMode === 'demo') {
    eventsList = [...MOCK_EVENTS];
    setCollectorStatus('Demo data selected', 'demo');
    return eventsList;
  }

  setCollectorStatus('Loading live events…', 'loading');
  try {
    const events = await TokenLineApi.getEvents();
    if (!Array.isArray(events)) throw new Error('Collector returned an invalid event response.');
    eventsList = events;
    setCollectorStatus('Collector connected · Live data', 'healthy');
    return eventsList;
  } catch (error) {
    eventsList = [];
    const authFailure = error.status === 401 || error.status === 403;
    setCollectorStatus(authFailure ? 'Authentication required' : 'Collector unavailable', authFailure ? 'auth' : 'error');
    throw error;
  }
}

function setupDataSettings() {
  const config = TokenLineApi.getConfig();
  const modeSelect = document.getElementById('setting-data-mode');
  const apiUrl = document.getElementById('setting-api-url');
  const apiKeyState = document.getElementById('api-key-state');
  const clearKey = document.getElementById('clear-api-key');
  const message = document.getElementById('settings-message');
  modeSelect.value = dataMode;
  apiUrl.value = config.baseUrl;
  apiKeyState.textContent = config.hasApiKey ? 'A key is saved for this tab.' : 'No API key saved for this tab.';

  modeSelect.addEventListener('change', () => {
    dataMode = modeSelect.value;
    sessionStorage.setItem('tokenline.dataMode', dataMode);
    loadDashboardData();
  });

  document.getElementById('save-api-settings').addEventListener('click', () => {
    try {
      const keyInput = document.getElementById('setting-api-key');
      const updated = TokenLineApi.configure({
        baseUrl: apiUrl.value,
        apiKey: keyInput.value,
        clearApiKey: clearKey.checked,
      });
      keyInput.value = '';
      clearKey.checked = false;
      apiUrl.value = updated.baseUrl;
      apiKeyState.textContent = updated.hasApiKey ? 'A key is saved for this tab.' : 'No API key saved for this tab.';
      message.textContent = 'Settings saved. Connecting to the collector…';
      dataMode = modeSelect.value;
      sessionStorage.setItem('tokenline.dataMode', dataMode);
      loadDashboardData();
    } catch (error) {
      message.textContent = error.message;
    }
  });
}

// --- 1. DASHBOARD LOADERS ---
async function loadDashboardData() {
  ['metric-active', 'metric-alerts', 'metric-revoked', 'metric-sessions'].forEach(id => {
    document.getElementById(id).textContent = '—';
  });
  showTableMessage(dataMode === 'demo' ? 'Loading demo events…' : 'Loading live events…');
  let events;
  let families = {};
  try {
    events = await getEvents();
    if (dataMode === 'live') {
      families = await TokenLineApi.getFamilies();
      if (!families || typeof families !== 'object' || Array.isArray(families)) {
        throw new Error('Collector returned an invalid token family response.');
      }
    }
  } catch (error) {
    const authFailure = error.status === 401 || error.status === 403;
    setCollectorStatus(authFailure ? 'Authentication required' : 'Collector unavailable', authFailure ? 'auth' : 'error');
    ['metric-active', 'metric-alerts', 'metric-revoked', 'metric-sessions'].forEach(id => {
      document.getElementById(id).textContent = '—';
    });
    showTableMessage(error.message);
    return;
  }
  
  // Calculate summary metrics
  const rotatedTokens = new Set(events.map(event => event.parent_token_hash).filter(Boolean));
  const latestEventByToken = new Map();
  [...events].sort((a, b) => new Date(b.time) - new Date(a.time)).forEach(event => {
    if (event.token_hash && !latestEventByToken.has(event.token_hash)) {
      latestEventByToken.set(event.token_hash, event);
    }
  });
  const activeCount = dataMode === 'live'
    ? Object.values(families).flat().filter(token => token.status === 'active').length
    : [...latestEventByToken.entries()].filter(([tokenHash, event]) =>
      event.result === 'accepted' &&
      !rotatedTokens.has(tokenHash) &&
      !['logout', 'token_expired', 'token_revoked'].includes(event.event_type)
    ).length;
  const alertCount = events.filter(e => 
    e.event_type.includes('reuse') || 
    (e.event_type.includes('expired') && e.event_type !== 'token_expired') || 
    e.event_type.includes('suspicious') || 
    e.event_type.includes('replay') ||
    (e.event_type === 'token_used' && e.result === 'rejected')
  ).length;
  const revokedCount = new Set(events
    .filter(e => e.event_type === 'token_revoked' || e.event_type === 'logout')
    .map(e => e.token_hash)
    .filter(Boolean)).size;
  const sessionsCount = dataMode === 'live'
    ? Object.keys(families).length
    : new Set(events.map(e => e.token_family).filter(Boolean)).size;

  // Render values
  document.getElementById('metric-active').textContent = activeCount;
  document.getElementById('metric-alerts').textContent = alertCount;
  document.getElementById('metric-revoked').textContent = revokedCount;
  document.getElementById('metric-sessions').textContent = sessionsCount;

  // Render recent activity feed
  eventFeedTable.textContent = '';
  if (events.length === 0) {
    showTableMessage(dataMode === 'demo' ? 'No demo events are available.' : 'No events are stored in the collector yet.');
    return;
  }
  [...events]
    .sort((a, b) => new Date(b.time) - new Date(a.time))
    .slice(0, 8)
    .forEach(event => {
    const tr = document.createElement('tr');
    
    // Severity mapping
    let pillClass = 'success';
    if (event.result === 'rejected' || (event.event_type && (event.event_type.includes('reuse') || event.event_type.includes('replay') || event.event_type.includes('suspicious')))) {
      pillClass = 'danger';
    }

    const tdType = document.createElement('td');
    const pill = document.createElement('span');
    pill.className = `pill ${pillClass}`;
    pill.textContent = (event.event_type || '').replace(/_/g, ' ');
    tdType.appendChild(pill);
    tr.appendChild(tdType);

    const tdTime = document.createElement('td');
    tdTime.textContent = formatDate(event.time);
    tr.appendChild(tdTime);

    const tdUser = document.createElement('td');
    const userStrong = document.createElement('strong');
    userStrong.textContent = event.user_id || '';
    tdUser.appendChild(userStrong);
    tr.appendChild(tdUser);

    const tdToken = document.createElement('td');
    tdToken.className = 'code-font';
    tdToken.textContent = maskToken(event.token_hash);
    tr.appendChild(tdToken);

    const tdIp = document.createElement('td');
    const ipSpan = document.createElement('span');
    ipSpan.className = 'code-font';
    ipSpan.textContent = event.ip_hash || '';
    tdIp.appendChild(ipSpan);
    tr.appendChild(tdIp);

    const tdRes = document.createElement('td');
    tdRes.textContent = event.result === 'accepted' ? '🟢 Accepted' : '🔴 Rejected';
    tr.appendChild(tdRes);

    tr.style.cursor = 'pointer';
    tr.addEventListener('click', () => {
      renderTimelineForToken(event.token_hash);
      switchTab('timeline');
    });

    eventFeedTable.appendChild(tr);
  });
}

// --- 2. TIMELINE VISUALIZER ---
async function renderTimelineForToken(tokenHash) {
  let events;
  try {
    events = await getEvents();
  } catch (error) {
    showTableMessage(error.message, document.getElementById('timeline-flow-container'));
    return;
  }
  document.getElementById('current-chain-id').textContent = maskToken(tokenHash);

  // Find the family for this token
  const currentEvent = events.find(e => e.token_hash === tokenHash || e.parent_token_hash === tokenHash);
  if (!currentEvent) {
    const flowContainer = document.getElementById('timeline-flow-container');
    flowContainer.textContent = '';
    const placeholderP = document.createElement('p');
    placeholderP.className = 'placeholder-text';
    placeholderP.textContent = 'Token ID not found in database logs.';
    flowContainer.appendChild(placeholderP);

    document.getElementById('family-tree-nodes').textContent = '';
    return;
  }
  const familyId = currentEvent.token_family;

  // Filter all events belonging to the same family and sort chronologically
  const familyEvents = events.filter(e => e.token_family === familyId).sort((a, b) => new Date(a.time) - new Date(b.time));

  // Render vertical timeline nodes
  const flowContainer = document.getElementById('timeline-flow-container');
  flowContainer.textContent = '';

  familyEvents.forEach(event => {
    const isAnomaly = event.result === 'rejected' || event.event_type.includes('reuse') || event.event_type.includes('suspicious');
    const nodeClass = isAnomaly ? 'danger' : 'success';

    const node = document.createElement('div');
    node.className = `timeline-node ${nodeClass}`;
    
    const marker = document.createElement('div');
    marker.className = 'timeline-marker';
    node.appendChild(marker);

    const card = document.createElement('div');
    card.className = 'timeline-card';

    const header = document.createElement('div');
    header.className = 'timeline-node-header';

    const h4 = document.createElement('h4');
    h4.textContent = (event.event_type || '').replace(/_/g, ' ').toUpperCase();
    header.appendChild(h4);

    const timeSpan = document.createElement('span');
    timeSpan.className = 'timeline-time';
    timeSpan.textContent = formatDate(event.time);
    header.appendChild(timeSpan);

    card.appendChild(header);

    const p = document.createElement('p');
    p.textContent = 'Token ID: ';
    const codeSpan = document.createElement('span');
    codeSpan.className = 'code-font';
    codeSpan.textContent = maskToken(event.token_hash);
    p.appendChild(codeSpan);
    p.appendChild(document.createTextNode(` (${event.user_id || ''})`));
    card.appendChild(p);

    card.addEventListener('click', () => {
      showEventDetails(event);
    });

    node.appendChild(card);
    flowContainer.appendChild(node);
  });

  // Render Token Family Linkage hierarchy
  const treeContainer = document.getElementById('family-tree-nodes');
  treeContainer.textContent = '';

  const uniqueTokens = Array.from(new Set(familyEvents.map(e => e.token_hash)));
  uniqueTokens.forEach(tHash => {
    const ev = familyEvents.find(e => e.token_hash === tHash);
    const nodeDiv = document.createElement('div');
    
    let stateClass = '';
    let label = 'Active';
    if (ev.event_type === 'refresh_reuse_detected') {
      stateClass = 'reused';
      label = 'Reused/Abused';
    } else if (familyEvents.some(e => e.parent_token_hash === tHash)) {
      stateClass = 'active'; // rotated
      label = 'Rotated';
    }

    nodeDiv.className = `tree-node ${stateClass}`;
    nodeDiv.textContent = '';

    const tokenSpan = document.createElement('span');
    tokenSpan.textContent = maskToken(tHash);
    nodeDiv.appendChild(tokenSpan);

    const badgeSpan = document.createElement('span');
    badgeSpan.className = 'badge offline';
    badgeSpan.textContent = label;
    nodeDiv.appendChild(badgeSpan);

    treeContainer.appendChild(nodeDiv);
  });

  // Render default first event context
  if (familyEvents.length > 0) {
    showEventDetails(familyEvents[0]);
  }
}

function showEventDetails(event) {
  selectedTimelineEvent = event;
  const detailPanel = document.getElementById('timeline-detail-content');
  
  // Custom metadata messages based on event type
  let rationale = "Operation succeeded under normal conditions.";
  if (event.event_type === 'refresh_reuse_detected') {
    rationale = `CRITICAL ALERT: Token was previously rotated and has already expired. Replay attempt rejected at ${formatDate(event.time)}.`;
  } else if (event.event_type === 'suspicious_location') {
    rationale = `WARN: Access accepted but geocontext shifted to ${event.country} from proxy terminal ID ${event.device_id}.`;
  } else if (event.event_type === 'token_expired') {
    rationale = `DENIED: Access rejected because token expired at ${formatDate(event.time)}.`;
  }

  detailPanel.textContent = '';

  const wrap = document.createElement('div');
  wrap.style.cssText = 'display:flex; flex-direction:column; gap:12px;';

  const addDetailRow = (label, val, isCode = false, isPill = false, extraText = '') => {
    const row = document.createElement('div');
    const strong = document.createElement('strong');
    strong.textContent = label + ': ';
    row.appendChild(strong);

    if (isPill) {
      const pill = document.createElement('span');
      pill.className = `pill ${event.result === 'accepted' ? 'success' : 'danger'}`;
      pill.textContent = val || '';
      row.appendChild(pill);
    } else if (isCode) {
      const span = document.createElement('span');
      span.className = 'code-font';
      span.textContent = val || '';
      row.appendChild(span);
    } else {
      row.appendChild(document.createTextNode(val || ''));
    }

    if (extraText) {
      row.appendChild(document.createTextNode(extraText));
    }
    wrap.appendChild(row);
  };

  addDetailRow('Event ID', event.event_id, true);
  addDetailRow('Action', event.event_type, false, true);
  addDetailRow('User', event.user_id);
  addDetailRow('Endpoint', event.endpoint, true);
  addDetailRow('IP Hash', event.ip_hash, true, false, event.country ? ` (${event.country})` : '');
  addDetailRow('User Agent', event.user_agent_family);
  addDetailRow('Device ID', event.device_id, true);

  const evidenceDiv = document.createElement('div');
  evidenceDiv.style.cssText = 'margin-top:10px; border-top:1px solid var(--color-border); padding-top:10px;';
  const evidenceStrong = document.createElement('strong');
  evidenceStrong.textContent = 'Detection Engine Evidence:';
  evidenceDiv.appendChild(evidenceStrong);

  const evidenceP = document.createElement('p');
  evidenceP.style.cssText = 'font-size:13px; margin-top:4px; opacity:0.8;';
  evidenceP.textContent = rationale;
  evidenceDiv.appendChild(evidenceP);

  wrap.appendChild(evidenceDiv);
  detailPanel.appendChild(wrap);
}

// --- 3. ALERTS VIEW & FILTERS ---
function setupAlertsView() {
  document.getElementById('filter-severity').addEventListener('change', renderAlerts);
  document.getElementById('filter-type').addEventListener('change', renderAlerts);
}

async function renderAlerts() {
  let events;
  try {
    events = await getEvents();
  } catch (error) {
    showTableMessage(error.message, document.getElementById('alerts-table-body'));
    return;
  }
  const severityFilter = document.getElementById('filter-severity').value;
  const typeFilter = document.getElementById('filter-type').value;
  const alertsTable = document.getElementById('alerts-table-body');
  
  alertsTable.textContent = '';

  // Extract alert events
  const alertEvents = events.filter(e => 
    e.event_type.includes('reuse') || 
    (e.event_type.includes('expired') && e.event_type !== 'token_expired') || 
    e.event_type.includes('suspicious') || 
    e.event_type.includes('replay') ||
    (e.event_type === 'token_used' && e.result === 'rejected')
  );

  alertEvents.forEach(alert => {
    // Map severity
    let severity = 'Medium';
    let severityClass = 'badge'; // default style
    if (alert.event_type.includes('reuse') || alert.event_type.includes('replay')) {
      severity = 'Critical';
      severityClass = 'badge'; // Cherry-like logic via CSS
    }

    // Apply Filter values
    if (severityFilter !== 'all' && severity.toLowerCase() !== severityFilter) return;
    if (typeFilter !== 'all' && alert.event_type !== typeFilter) return;

    const tr = document.createElement('tr');
    
    // Style severity tag inline to match the requested palette
    let severityStyle = 'background-color: var(--color-surface-alt); color: var(--color-text-primary); border: 1px solid var(--color-border); padding: 3px 9px; border-radius: 4px; display: inline-block;';
    if (severity === 'Critical') {
      severityStyle = 'background-color: var(--color-danger-bg); color: var(--color-danger); border: 1px solid var(--color-danger); padding: 3px 9px; border-radius: 4px; display: inline-block;';
    }

    const tdSev = document.createElement('td');
    const sevSpan = document.createElement('span');
    sevSpan.className = severityClass;
    sevSpan.style.cssText = severityStyle;
    sevSpan.textContent = severity;
    tdSev.appendChild(sevSpan);
    tr.appendChild(tdSev);

    const tdType = document.createElement('td');
    const strongType = document.createElement('strong');
    strongType.style.color = 'var(--color-danger)';
    strongType.textContent = (alert.event_type || '').replace(/_/g, ' ').toUpperCase();
    tdType.appendChild(strongType);
    tr.appendChild(tdType);

    const tdToken = document.createElement('td');
    tdToken.className = 'code-font';
    tdToken.textContent = maskToken(alert.token_hash);
    tr.appendChild(tdToken);

    const tdTime = document.createElement('td');
    tdTime.textContent = formatDate(alert.time);
    tr.appendChild(tdTime);

    const tdStatus = document.createElement('td');
    const statusPill = document.createElement('span');
    statusPill.className = 'pill danger';
    statusPill.textContent = 'active';
    tdStatus.appendChild(statusPill);
    tr.appendChild(tdStatus);

    const tdBtn = document.createElement('td');
    const btn = document.createElement('button');
    btn.className = 'nav-item active';
    btn.style.cssText = 'padding: 6px 12px; font-size:12px; border-radius:4px;';
    btn.textContent = 'Investigate';
    btn.addEventListener('click', () => {
      viewAlertToken(alert.token_hash);
    });
    tdBtn.appendChild(btn);
    tr.appendChild(tdBtn);

    alertsTable.appendChild(tr);
  });

  if (alertsTable.children.length === 0) {
    alertsTable.textContent = '';
    const tr = document.createElement('tr');
    const td = document.createElement('td');
    td.colSpan = 6;
    td.className = 'placeholder-text';
    td.style.textAlign = 'center';
    td.textContent = 'No matching security alerts found.';
    tr.appendChild(td);
    alertsTable.appendChild(tr);
  }
}

window.viewAlertToken = function(tHash) {
  renderTimelineForToken(tHash);
  switchTab('timeline');
};

// --- 4. TOP BAR SEARCH ---
function setupSearch() {
  tokenSearchInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      const query = tokenSearchInput.value.trim();
      if (query) {
        renderTimelineForToken(query);
        switchTab('timeline');
      }
    }
  });
}
