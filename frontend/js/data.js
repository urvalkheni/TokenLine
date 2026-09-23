/**
 * TokenLine Data Module - Live API Client & Deterministic Scenario Fixtures
 */
const API_BASE = '/api';

// --- BUILT-IN DETERMINISTIC SYNTHETIC FIXTURES (Generated from Local Simulator) ---
const SCENARIO_FIXTURES = {
  "replay": [
    {
      "event_id": "evt-replay-001",
      "event_type": "token_issued",
      "time": "2026-08-16T10:00:00Z",
      "user_id": "user-synthetic-01",
      "token_hash": "hash_6a438e0305c7",
      "token_family": "family-replay-42",
      "ip_hash": "hash_18ac8b418b9c",
      "country": "US",
      "device_id": "device-legit-laptop",
      "user_agent_family": "Chrome",
      "endpoint": "/api/auth/login",
      "result": "accepted"
    },
    {
      "event_id": "evt-replay-002",
      "event_type": "token_used",
      "time": "2026-08-16T10:02:00Z",
      "user_id": "user-synthetic-01",
      "token_hash": "hash_6a438e0305c7",
      "token_family": "family-replay-42",
      "ip_hash": "hash_18ac8b418b9c",
      "country": "US",
      "device_id": "device-legit-laptop",
      "user_agent_family": "Chrome",
      "endpoint": "/api/v1/profile",
      "result": "accepted"
    },
    {
      "event_id": "evt-replay-003",
      "event_type": "token_used",
      "time": "2026-08-16T10:04:00Z",
      "user_id": "user-synthetic-01",
      "token_hash": "hash_6a438e0305c7",
      "token_family": "family-replay-42",
      "ip_hash": "hash_18ac8b418b9c",
      "country": "US",
      "device_id": "device-legit-laptop",
      "user_agent_family": "Chrome",
      "endpoint": "/api/v1/dashboard",
      "result": "accepted"
    },
    {
      "event_id": "evt-replay-004",
      "event_type": "replay_detected",
      "time": "2026-08-16T10:05:00Z",
      "user_id": "user-synthetic-01",
      "token_hash": "hash_6a438e0305c7",
      "token_family": "family-replay-42",
      "ip_hash": "hash_f74d055116b4",
      "country": "RO",
      "device_id": "device-unknown-adversary",
      "user_agent_family": "Python-requests",
      "endpoint": "/api/v1/wallet",
      "result": "rejected"
    }
  ],
  "refresh-reuse": [
    {
      "event_id": "evt-reuse-001",
      "event_type": "token_issued",
      "time": "2026-08-16T10:00:00Z",
      "user_id": "user-synthetic-02",
      "token_hash": "hash_a11fa3b59b12",
      "token_family": "family-refresh-42",
      "ip_hash": "hash_c98da1ef8273",
      "country": "US",
      "device_id": "device-user-phone",
      "user_agent_family": "MobileSafari",
      "endpoint": "/api/auth/login",
      "result": "accepted"
    },
    {
      "event_id": "evt-reuse-002",
      "event_type": "token_used",
      "time": "2026-08-16T10:05:00Z",
      "user_id": "user-synthetic-02",
      "token_hash": "hash_a11fa3b59b12",
      "token_family": "family-refresh-42",
      "ip_hash": "hash_c98da1ef8273",
      "country": "US",
      "device_id": "device-user-phone",
      "user_agent_family": "MobileSafari",
      "endpoint": "/api/v1/feed",
      "result": "accepted"
    },
    {
      "event_id": "evt-reuse-003",
      "event_type": "token_refreshed",
      "time": "2026-08-16T10:30:00Z",
      "user_id": "user-synthetic-02",
      "token_hash": "hash_b22ec4d61084",
      "parent_token_hash": "hash_a11fa3b59b12",
      "token_family": "family-refresh-42",
      "ip_hash": "hash_c98da1ef8273",
      "country": "US",
      "device_id": "device-user-phone",
      "user_agent_family": "MobileSafari",
      "endpoint": "/api/auth/refresh",
      "result": "accepted"
    },
    {
      "event_id": "evt-reuse-004",
      "event_type": "token_used",
      "time": "2026-08-16T10:33:20Z",
      "user_id": "user-synthetic-02",
      "token_hash": "hash_b22ec4d61084",
      "token_family": "family-refresh-42",
      "ip_hash": "hash_c98da1ef8273",
      "country": "US",
      "device_id": "device-user-phone",
      "user_agent_family": "MobileSafari",
      "endpoint": "/api/v1/feed",
      "result": "accepted"
    },
    {
      "event_id": "evt-reuse-005",
      "event_type": "token_refreshed",
      "time": "2026-08-16T10:35:00Z",
      "user_id": "user-synthetic-02",
      "token_hash": "hash_c33fd5e72195",
      "parent_token_hash": "hash_a11fa3b59b12",
      "token_family": "family-refresh-42",
      "ip_hash": "hash_d44aa811bc23",
      "country": "RU",
      "device_id": "device-adversary-bot",
      "user_agent_family": "Curl",
      "endpoint": "/api/auth/refresh",
      "result": "rejected"
    }
  ],
  "revoked-token": [
    {
      "event_id": "evt-logout-001",
      "event_type": "token_issued",
      "time": "2026-08-16T10:00:00Z",
      "user_id": "user-synthetic-03",
      "token_hash": "hash_rev_tok_001",
      "token_family": "family-logout-42",
      "ip_hash": "hash_ip_office_42",
      "country": "US",
      "device_id": "device-workstation-01",
      "user_agent_family": "Firefox",
      "endpoint": "/api/auth/login",
      "result": "accepted"
    },
    {
      "event_id": "evt-logout-002",
      "event_type": "token_used",
      "time": "2026-08-16T10:05:00Z",
      "user_id": "user-synthetic-03",
      "token_hash": "hash_rev_tok_001",
      "token_family": "family-logout-42",
      "ip_hash": "hash_ip_office_42",
      "country": "US",
      "device_id": "device-workstation-01",
      "user_agent_family": "Firefox",
      "endpoint": "/api/v1/projects",
      "result": "accepted"
    },
    {
      "event_id": "evt-logout-003",
      "event_type": "logout",
      "time": "2026-08-16T10:15:00Z",
      "user_id": "user-synthetic-03",
      "token_hash": "hash_rev_tok_001",
      "token_family": "family-logout-42",
      "ip_hash": "hash_ip_office_42",
      "country": "US",
      "device_id": "device-workstation-01",
      "user_agent_family": "Firefox",
      "endpoint": "/api/auth/logout",
      "result": "accepted"
    },
    {
      "event_id": "evt-logout-004",
      "event_type": "token_used",
      "time": "2026-08-16T10:16:00Z",
      "user_id": "user-synthetic-03",
      "token_hash": "hash_rev_tok_001",
      "token_family": "family-logout-42",
      "ip_hash": "hash_ip_office_42",
      "country": "US",
      "device_id": "device-workstation-01",
      "user_agent_family": "Firefox",
      "endpoint": "/api/v1/projects",
      "result": "rejected"
    }
  ],
  "concurrent-use": [
    {
      "event_id": "evt-concurrent-001",
      "event_type": "token_issued",
      "time": "2026-08-16T10:00:00Z",
      "user_id": "user-synthetic-04",
      "token_hash": "hash_concurrent_tok",
      "token_family": "family-concurrent-42",
      "ip_hash": "hash_office_lan",
      "country": "US",
      "device_id": "device-workstation-office",
      "user_agent_family": "Edge",
      "endpoint": "/api/auth/login",
      "result": "accepted"
    },
    {
      "event_id": "evt-concurrent-002",
      "event_type": "token_used",
      "time": "2026-08-16T10:01:00Z",
      "user_id": "user-synthetic-04",
      "token_hash": "hash_concurrent_tok",
      "token_family": "family-concurrent-42",
      "ip_hash": "hash_office_lan",
      "country": "US",
      "device_id": "device-workstation-office",
      "user_agent_family": "Edge",
      "endpoint": "/api/v1/documents",
      "result": "accepted"
    },
    {
      "event_id": "evt-concurrent-003",
      "event_type": "token_used",
      "time": "2026-08-16T10:01:05Z",
      "user_id": "user-synthetic-04",
      "token_hash": "hash_concurrent_tok",
      "token_family": "family-concurrent-42",
      "ip_hash": "hash_remote_tunnel",
      "country": "DE",
      "device_id": "device-rogue-clone",
      "user_agent_family": "Go-http-client",
      "endpoint": "/api/v1/documents/export",
      "result": "accepted"
    },
    {
      "event_id": "evt-concurrent-004",
      "event_type": "suspicious_device",
      "time": "2026-08-16T10:01:10Z",
      "user_id": "user-synthetic-04",
      "token_hash": "hash_concurrent_tok",
      "token_family": "family-concurrent-42",
      "ip_hash": "hash_remote_tunnel",
      "country": "DE",
      "device_id": "device-rogue-clone",
      "user_agent_family": "Go-http-client",
      "endpoint": "/api/v1/documents/export",
      "result": "rejected"
    }
  ],
  "impossible-travel": [
    {
      "event_id": "evt-travel-001",
      "event_type": "token_issued",
      "time": "2026-08-16T10:00:00Z",
      "user_id": "user-synthetic-05",
      "token_hash": "hash_travel_tok_42",
      "token_family": "family-travel-42",
      "ip_hash": "hash_mumbai_isp",
      "country": "IN",
      "device_id": "device-traveler-laptop",
      "user_agent_family": "Chrome",
      "endpoint": "/api/auth/login",
      "result": "accepted"
    },
    {
      "event_id": "evt-travel-002",
      "event_type": "token_used",
      "time": "2026-08-16T10:01:00Z",
      "user_id": "user-synthetic-05",
      "token_hash": "hash_travel_tok_42",
      "token_family": "family-travel-42",
      "ip_hash": "hash_mumbai_isp",
      "country": "IN",
      "device_id": "device-traveler-laptop",
      "user_agent_family": "Chrome",
      "endpoint": "/api/v1/profile",
      "result": "accepted"
    },
    {
      "event_id": "evt-travel-003",
      "event_type": "suspicious_location",
      "time": "2026-08-16T10:05:00Z",
      "user_id": "user-synthetic-05",
      "token_hash": "hash_travel_tok_42",
      "token_family": "family-travel-42",
      "ip_hash": "hash_ny_datacenter",
      "country": "US",
      "device_id": "device-traveler-laptop",
      "user_agent_family": "Chrome",
      "endpoint": "/api/v1/profile",
      "result": "rejected"
    }
  ]
};

// --- INITIAL EMBEDDED FAMILIES ---
const INITIAL_FAMILIES = {
  "family-khushi-1": [
    {
      "token_hash": "token_hash_a1b2c3d4",
      "token_family": "family-khushi-1",
      "parent_token_hash": null,
      "superseded_by": "token_hash_e5f6g7h8",
      "status": "reused",
      "issued_at": "2026-08-16T10:00:00Z",
      "rotated_at": "2026-08-16T10:30:00Z",
      "user_id": "user-khushi",
      "reuse_details": {
        "reused_at": "2026-08-16T10:36:00Z",
        "attempted_event_id": "evt-005"
      }
    },
    {
      "token_hash": "token_hash_e5f6g7h8",
      "token_family": "family-khushi-1",
      "parent_token_hash": "token_hash_a1b2c3d4",
      "superseded_by": null,
      "status": "active",
      "issued_at": "2026-08-16T10:30:00Z",
      "user_id": "user-khushi"
    }
  ],
  "family-alpha-rotation": [
    {
      "token_hash": "tok_alpha_root_01",
      "token_family": "family-alpha-rotation",
      "parent_token_hash": null,
      "superseded_by": "tok_alpha_child_02",
      "status": "rotated",
      "issued_at": "2026-08-16T09:00:00Z",
      "rotated_at": "2026-08-16T09:20:00Z",
      "user_id": "user-alpha"
    },
    {
      "token_hash": "tok_alpha_child_02",
      "token_family": "family-alpha-rotation",
      "parent_token_hash": "tok_alpha_root_01",
      "superseded_by": "tok_alpha_child_03",
      "status": "rotated",
      "issued_at": "2026-08-16T09:20:00Z",
      "rotated_at": "2026-08-16T09:45:00Z",
      "user_id": "user-alpha"
    },
    {
      "token_hash": "tok_alpha_child_03",
      "token_family": "family-alpha-rotation",
      "parent_token_hash": "tok_alpha_child_02",
      "superseded_by": null,
      "status": "active",
      "issued_at": "2026-08-16T09:45:00Z",
      "user_id": "user-alpha"
    }
  ],
  "family-long-chain-20": Array.from({ length: 22 }, (_, i) => ({
    token_hash: `tok_long_chain_node_${String(i + 1).padStart(2, '0')}`,
    token_family: "family-long-chain-20",
    parent_token_hash: i === 0 ? null : `tok_long_chain_node_${String(i).padStart(2, '0')}`,
    superseded_by: i === 21 ? null : `tok_long_chain_node_${String(i + 2).padStart(2, '0')}`,
    status: i === 21 ? "active" : "rotated",
    issued_at: `2026-08-16T${String(8 + Math.floor(i / 2)).padStart(2, '0')}:${(i % 2) * 30}:00Z`,
    user_id: "user-stress-test"
  }))
};

// Flatten initial events
const INITIAL_EVENTS = [
  ...SCENARIO_FIXTURES["replay"],
  ...SCENARIO_FIXTURES["refresh-reuse"],
  ...SCENARIO_FIXTURES["revoked-token"],
  ...SCENARIO_FIXTURES["concurrent-use"],
  ...SCENARIO_FIXTURES["impossible-travel"]
];

const TokenDataService = {
  async getEvents() {
    try {
      const res = await fetch(`${API_BASE}/events?limit=100`);
      if (res.ok) {
        const data = await res.json();
        if (data && data.length > 0) return data;
      }
    } catch (e) {
      // Fallback
    }
    return INITIAL_EVENTS;
  },

  async getFamilies() {
    try {
      const res = await fetch(`${API_BASE}/families`);
      if (res.ok) {
        const data = await res.json();
        if (data && Object.keys(data).length > 0) return data;
      }
    } catch (e) {
      // Fallback
    }
    return INITIAL_FAMILIES;
  },

  async getFamilyDetail(familyId) {
    try {
      const res = await fetch(`${API_BASE}/families/${familyId}`);
      if (res.ok) return await res.json();
    } catch (e) {
      // Fallback
    }
    if (INITIAL_FAMILIES[familyId]) {
      return {
        token_family: familyId,
        tokens: INITIAL_FAMILIES[familyId],
        chain: INITIAL_FAMILIES[familyId].map(t => t.token_hash),
        reuse_count: INITIAL_FAMILIES[familyId].filter(t => t.status === 'reused').length
      };
    }
    return null;
  },

  async getScenarios() {
    return [
      {
        id: "replay",
        name: "Token Replay",
        description: "Valid token is issued and used legitimately, then replayed by an adversary from an unauthorized host.",
        detection_signal: "replay_detected"
      },
      {
        id: "refresh-reuse",
        name: "Refresh-Token Reuse",
        description: "Legitimate rotation from Token A to Token B, followed by adversary presenting rotated Token A to request a new token.",
        detection_signal: "token_refreshed (flags reuse record)"
      },
      {
        id: "revoked-token",
        name: "Use After Logout",
        description: "User logs in, accesses resources, terminates session via logout, then adversary presents the revoked token.",
        detection_signal: "logout -> token_used (rejected)"
      },
      {
        id: "concurrent-use",
        name: "Concurrent Use",
        description: "The same authentication token is presented almost simultaneously from two distinct physical devices/IPs.",
        detection_signal: "suspicious_device"
      },
      {
        id: "impossible-travel",
        name: "Impossible Travel",
        description: "Same token presented from distant geographical coordinates (India to US) within an impossibly brief 5-minute window.",
        detection_signal: "suspicious_location"
      }
    ];
  },

  async runScenario(scenarioId) {
    try {
      const res = await fetch(`${API_BASE}/scenarios/${scenarioId}/run`, { method: 'POST' });
      if (res.ok) {
        const data = await res.json();
        return data.events;
      }
    } catch (e) {
      // Fallback
    }
    return SCENARIO_FIXTURES[scenarioId] || [];
  }
};
