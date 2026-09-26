/**
 * TokenLine Dashboard - Core Logic (HTML Integration & UI Shell Scaffolding)
 * 
 * NOTE: This is currently using mock data. Look for "[API INTEGRATION POINT]" 
 * comments below to wire this up to the Python Event Collector REST API.
 */

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
let eventsList = [...MOCK_EVENTS];
let selectedTimelineEvent = null;

// --- DOM ELEMENT REFERENCES ---
const navItems = document.querySelectorAll('.nav-item');
const tabViews = document.querySelectorAll('.tab-view');
const eventFeedTable = document.getElementById('dashboard-event-feed');
const tokenSearchInput = document.getElementById('token-search');

// --- APP INITIALIZATION ---
document.addEventListener('DOMContentLoaded', () => {
  setupNavigation();
  setupSearch();
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

function getEvents() {
  return fetch('http://127.0.0.1:5000/events')
    .then(res => res.json())
    .then(data => {
      eventsList = data; // Update global state
      return data;
    })
    .catch(err => {
      console.error('Failed to fetch live events, falling back to mock data:', err);
      return eventsList; 
    });
}

// --- 1. DASHBOARD LOADERS ---
async function loadDashboardData() {
  const events = await getEvents();
  
  // Calculate summary metrics
  const activeCount = new Set(events.filter(e => e.result === 'accepted' && e.event_type !== 'logout' && e.event_type !== 'token_expired').map(e => e.token_hash)).size;
  const alertCount = events.filter(e => e.event_type.includes('reuse') || e.event_type.includes('expired') || e.event_type.includes('suspicious') || e.event_type.includes('replay')).length;
  const revokedCount = events.filter(e => e.event_type === 'token_revoked' || e.result === 'rejected').length;
  const sessionsCount = new Set(events.map(e => e.token_family)).size;

  // Render values
  document.getElementById('metric-active').textContent = activeCount;
  document.getElementById('metric-alerts').textContent = alertCount;
  document.getElementById('metric-revoked').textContent = revokedCount;
  document.getElementById('metric-sessions').textContent = sessionsCount;

  // Render recent activity feed
  eventFeedTable.innerHTML = '';
  events.slice(-8).reverse().forEach(event => {
    const tr = document.createElement('tr');
    
    // Severity mapping
    let pillClass = 'success';
    if (event.result === 'rejected' || event.event_type.includes('reuse') || event.event_type.includes('replay') || event.event_type.includes('suspicious')) {
      pillClass = 'danger';
    }

    tr.innerHTML = `
      <td><span class="pill ${pillClass}">${event.event_type.replace(/_/g, ' ')}</span></td>
      <td>${formatDate(event.time)}</td>
      <td><strong>${event.user_id}</strong></td>
      <td class="code-font">${maskToken(event.token_hash)}</td>
      <td><span class="code-font">${event.ip_hash}</span></td>
      <td>${event.result === 'accepted' ? '🟢 Accepted' : '🔴 Rejected'}</td>
    `;

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
  const events = await getEvents();
  document.getElementById('current-chain-id').textContent = maskToken(tokenHash);

  // Find the family for this token
  const currentEvent = events.find(e => e.token_hash === tokenHash || e.parent_token_hash === tokenHash);
  if (!currentEvent) {
    document.getElementById('timeline-flow-container').innerHTML = '<p class="placeholder-text">Token ID not found in database logs.</p>';
    document.getElementById('family-tree-nodes').innerHTML = '';
    return;
  }
  const familyId = currentEvent.token_family;

  // Filter all events belonging to the same family and sort chronologically
  const familyEvents = events.filter(e => e.token_family === familyId).sort((a, b) => new Date(a.time) - new Date(b.time));

  // Render vertical timeline nodes
  const flowContainer = document.getElementById('timeline-flow-container');
  flowContainer.innerHTML = '';

  familyEvents.forEach(event => {
    const isAnomaly = event.result === 'rejected' || event.event_type.includes('reuse') || event.event_type.includes('suspicious');
    const nodeClass = isAnomaly ? 'danger' : 'success';

    const node = document.createElement('div');
    node.className = `timeline-node ${nodeClass}`;
    
    node.innerHTML = `
      <div class="timeline-marker"></div>
      <div class="timeline-card">
        <div class="timeline-node-header">
          <h4>${event.event_type.replace(/_/g, ' ').toUpperCase()}</h4>
          <span class="timeline-time">${formatDate(event.time)}</span>
        </div>
        <p>Token ID: <span class="code-font">${maskToken(event.token_hash)}</span> (${event.user_id})</p>
      </div>
    `;

    node.querySelector('.timeline-card').addEventListener('click', () => {
      showEventDetails(event);
    });

    flowContainer.appendChild(node);
  });

  // Render Token Family Linkage hierarchy
  const treeContainer = document.getElementById('family-tree-nodes');
  treeContainer.innerHTML = '';

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
    nodeDiv.innerHTML = `
      <span>${maskToken(tHash)}</span>
      <span class="badge offline">${label}</span>
    `;
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

  detailPanel.innerHTML = `
    <div style="display:flex; flex-direction:column; gap:12px;">
      <div><strong>Event ID:</strong> <span class="code-font">${event.event_id}</span></div>
      <div><strong>Action:</strong> <span class="pill ${event.result === 'accepted' ? 'success' : 'danger'}">${event.event_type}</span></div>
      <div><strong>User:</strong> ${event.user_id}</div>
      <div><strong>Endpoint:</strong> <span class="code-font">${event.endpoint}</span></div>
      <div><strong>IP Hash:</strong> <span class="code-font">${event.ip_hash} (${event.country})</span></div>
      <div><strong>User Agent:</strong> ${event.user_agent_family}</div>
      <div><strong>Device ID:</strong> <span class="code-font">${event.device_id}</span></div>
      <div style="margin-top:10px; border-top:1px solid var(--color-border); padding-top:10px;">
        <strong>Detection Engine Evidence:</strong>
        <p style="font-size:13px; margin-top:4px; opacity:0.8;">${rationale}</p>
      </div>
    </div>
  `;
}

// --- 3. ALERTS VIEW & FILTERS ---
function setupAlertsView() {
  document.getElementById('filter-severity').addEventListener('change', renderAlerts);
  document.getElementById('filter-type').addEventListener('change', renderAlerts);
}

async function renderAlerts() {
  const events = await getEvents();
  const severityFilter = document.getElementById('filter-severity').value;
  const typeFilter = document.getElementById('filter-type').value;
  const alertsTable = document.getElementById('alerts-table-body');
  
  alertsTable.innerHTML = '';

  // Extract alert events
  const alertEvents = events.filter(e => 
    e.event_type.includes('reuse') || 
    e.event_type.includes('expired') || 
    e.event_type.includes('suspicious') || 
    e.event_type.includes('replay')
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

    tr.innerHTML = `
      <td><span class="${severityClass}" style="${severityStyle}">${severity}</span></td>
      <td><strong style="color:var(--color-danger);">${alert.event_type.replace(/_/g, ' ').toUpperCase()}</strong></td>
      <td class="code-font">${maskToken(alert.token_hash)}</td>
      <td>${formatDate(alert.time)}</td>
      <td><span class="pill danger">active</span></td>
      <td><button class="nav-item active" style="padding: 6px 12px; font-size:12px; border-radius:4px;" onclick="viewAlertToken('${alert.token_hash}')">Investigate</button></td>
    `;

    alertsTable.appendChild(tr);
  });

  if (alertsTable.children.length === 0) {
    alertsTable.innerHTML = '<tr><td colspan="6" class="placeholder-text" style="text-align:center;">No matching security alerts found.</td></tr>';
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
