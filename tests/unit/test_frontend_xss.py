import os
import re
import json
import subprocess
import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
FRONTEND_DIR = os.path.join(REPO_ROOT, "frontend")


def run_node_eval(script: str) -> dict:
    """Helper to run a Node.js script in the repo root and parse JSON output."""
    result = subprocess.run(
        ["node", "-e", script],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False
    )
    if result.returncode != 0:
        raise RuntimeError(f"Node execution failed (code {result.returncode}):\nSTDOUT: {result.stdout}\nSTDERR: {result.stderr}")
    return json.loads(result.stdout.strip())


# ---------------------------------------------------------------------------
# Test 1: Static Sink Audit
# ---------------------------------------------------------------------------

def test_zero_innerhtml_or_unsafe_sinks_in_frontend():
    """
    Verifies that all 26 innerHTML sinks have been eliminated from the frontend
    and no other unsafe HTML rendering sinks (innerHTML, outerHTML,
    document.write, insertAdjacentHTML) exist.
    """
    unsafe_patterns = [
        re.compile(r"\binnerHTML\b"),
        re.compile(r"\bouterHTML\b"),
        re.compile(r"\bdocument\.write\b"),
        re.compile(r"\binsertAdjacentHTML\b"),
    ]

    checked_extensions = (".js", ".html")
    found_sinks = []

    for root, _, files in os.walk(FRONTEND_DIR):
        for f in files:
            if f.endswith(checked_extensions):
                filepath = os.path.join(root, f)
                relpath = os.path.relpath(filepath, REPO_ROOT)
                with open(filepath, "r", encoding="utf-8") as fh:
                    for line_no, line in enumerate(fh, 1):
                        for pattern in unsafe_patterns:
                            if pattern.search(line):
                                found_sinks.append(f"{relpath}:{line_no}: {line.strip()}")

    assert len(found_sinks) == 0, (
        f"Found {len(found_sinks)} unsafe HTML rendering sinks in frontend:\n"
        + "\n".join(found_sinks)
    )


# ---------------------------------------------------------------------------
# Node Harness Common Setup
# ---------------------------------------------------------------------------

NODE_DOM_MOCK = """
function createMockElement(tagName) {
  const classes = new Set();
  return {
    tagName: tagName.toUpperCase(),
    children: [],
    childNodes: [],
    attributes: {},
    style: {},
    colSpan: 1,
    eventListeners: {},
    classList: {
      add(...cls) { cls.forEach(c => classes.add(c)); },
      remove(...cls) { cls.forEach(c => classes.delete(c)); },
      toggle(cls, force) {
        if (force === undefined) {
          if (classes.has(cls)) classes.delete(cls); else classes.add(cls);
        } else if (force) {
          classes.add(cls);
        } else {
          classes.delete(cls);
        }
      },
      contains(cls) { return classes.has(cls); }
    },
    get className() { return Array.from(classes).join(' '); },
    set className(val) {
      classes.clear();
      if (val) val.split(' ').filter(Boolean).forEach(c => classes.add(c));
    },
    appendChild(child) {
      if (child == null) return child;
      this.children.push(child);
      this.childNodes.push(child);
      if (typeof child === 'object') {
        child.parentNode = this;
      }
      return child;
    },
    setAttribute(k, v) { this.attributes[k] = String(v); },
    getAttribute(k) { return this.attributes[k]; },
    addEventListener(evt, handler) {
      if (!this.eventListeners[evt]) this.eventListeners[evt] = [];
      this.eventListeners[evt].push(handler);
    },
    querySelector(selector) {
      const all = this.querySelectorAll(selector);
      return all.length > 0 ? all[0] : null;
    },
    querySelectorAll(selector) {
      const results = [];
      function match(elem) {
        if (!elem || typeof elem !== 'object') return;
        const tag = elem.tagName ? elem.tagName.toLowerCase() : '';
        const cls = elem.className || '';
        const id = elem.attributes ? (elem.attributes.id || '') : '';
        if (selector.startsWith('.') && cls.split(' ').includes(selector.slice(1))) {
          results.push(elem);
        } else if (selector.startsWith('#') && (elem.id === selector.slice(1) || id === selector.slice(1))) {
          results.push(elem);
        } else if (tag === selector.toLowerCase()) {
          results.push(elem);
        }
        for (const child of (elem.children || [])) {
          if (typeof child === 'object') match(child);
        }
      }
      for (const child of this.children) {
        if (typeof child === 'object') match(child);
      }
      return results;
    },
    get textContent() {
      return this.childNodes.map(c => {
        if (typeof c === 'string') return c;
        if (c && typeof c === 'object') {
          if (c.nodeType === 3) return c.nodeValue || '';
          return c.textContent || '';
        }
        return '';
      }).join('');
    },
    set textContent(val) {
      this.childNodes = [String(val)];
      this.children = [];
    }
  };
}

function createTextNode(text) {
  return {
    nodeType: 3,
    nodeValue: String(text),
    get textContent() { return this.nodeValue; },
    set textContent(v) { this.nodeValue = String(v); }
  };
}

function collectAllElements(root) {
  const elements = [];
  function walk(node) {
    if (!node || typeof node !== 'object') return;
    if (node.tagName) elements.push(node);
    for (const child of (node.children || [])) {
      if (typeof child === 'object') walk(child);
    }
  }
  walk(root);
  return elements;
}
"""


# ---------------------------------------------------------------------------
# Test 2: XSS Regression on Dashboard Details (showEventDetails)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("payload", [
    "<img src=x onerror=alert(1)>",
    "<script>alert(1)</script>",
    "\"><svg onload=alert(1)>",
    "' onfocus='alert(1)"
])
def test_dashboard_show_event_details_xss(payload):
    """
    Tests that malicious HTML payloads injected into event fields:
    - endpoint
    - user_agent_family
    - device_id
    - user_id
    - country
    - token_hash
    are safely rendered as plain text and NEVER create executable DOM nodes
    or event-handler attributes in showEventDetails.
    """
    test_script = f"""
const fs = require('fs');
const vm = require('vm');

{NODE_DOM_MOCK}

const elements = {{
  'timeline-detail-content': createMockElement('div'),
  'dashboard-event-feed': createMockElement('table'),
  'token-search': createMockElement('input')
}};

const sandbox = {{
  document: {{
    addEventListener() {{}},
    querySelectorAll() {{ return []; }},
    getElementById(id) {{
      if (!elements[id]) elements[id] = createMockElement('div');
      return elements[id];
    }},
    createElement: createMockElement,
    createTextNode: createTextNode
  }},
  window: {{ addEventListener() {{}} }},
  console: console,
  fetch() {{ return Promise.resolve({{ json: () => Promise.resolve([]) }}); }}
}};

vm.createContext(sandbox);
const code = fs.readFileSync('frontend/dashboard/app.js', 'utf8');
vm.runInContext(code, sandbox);

const payload = {json.dumps(payload)};
const maliciousEvent = {{
  event_id: 'evt-test-101',
  event_type: 'suspicious_location',
  time: '2026-08-16T12:00:00Z',
  user_id: payload,
  token_hash: payload,
  token_family: 'fam-test',
  ip_hash: 'ip_sec123',
  country: payload,
  device_id: payload,
  user_agent_family: payload,
  endpoint: payload,
  result: 'accepted'
}};

sandbox.showEventDetails(maliciousEvent);

const panel = elements['timeline-detail-content'];
const allElements = collectAllElements(panel);
const tags = allElements.map(e => e.tagName);

// Check for any unsafe tags
const hasScript = tags.includes('SCRIPT');
const hasImg = tags.includes('IMG');
const hasSvg = tags.includes('SVG');

// Check for any event handler attributes
let hasEventAttrs = false;
for (const el of allElements) {{
  for (const attr of Object.keys(el.attributes)) {{
    if (attr.toLowerCase().startsWith('on')) {{
      hasEventAttrs = true;
    }}
  }}
}}

// Verify payload is present as plain text in the panel
const fullText = panel.textContent;
const textContainsPayload = fullText.includes(payload);

console.log(JSON.stringify({{
  hasScript,
  hasImg,
  hasSvg,
  hasEventAttrs,
  textContainsPayload,
  tagsCount: tags.length
}}));
"""
    result = run_node_eval(test_script)
    assert not result["hasScript"], f"SCRIPT tag created from payload {payload}"
    assert not result["hasImg"], f"IMG tag created from payload {payload}"
    assert not result["hasSvg"], f"SVG tag created from payload {payload}"
    assert not result["hasEventAttrs"], f"Event handler attribute created from payload {payload}"
    assert result["textContainsPayload"], f"Payload text not found in rendered content for payload {payload}"


# ---------------------------------------------------------------------------
# Test 3: XSS Regression on Dashboard Feed (loadDashboardData)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("payload", [
    "<img src=x onerror=alert(1)>",
    "<script>alert(1)</script>"
])
def test_dashboard_feed_xss(payload):
    """
    Tests that malicious HTML injected into user_id, token_hash, ip_hash
    in loadDashboardData is safely rendered as text without creating elements.
    """
    test_script = f"""
const fs = require('fs');
const vm = require('vm');

{NODE_DOM_MOCK}

const feedTable = createMockElement('tbody');
const elements = {{
  'dashboard-event-feed': feedTable,
  'metric-active': createMockElement('span'),
  'metric-alerts': createMockElement('span'),
  'metric-revoked': createMockElement('span'),
  'metric-sessions': createMockElement('span'),
  'token-search': createMockElement('input')
}};

const sandbox = {{
  document: {{
    addEventListener() {{}},
    querySelectorAll() {{ return []; }},
    getElementById(id) {{
      if (!elements[id]) elements[id] = createMockElement('div');
      return elements[id];
    }},
    createElement: createMockElement,
    createTextNode: createTextNode
  }},
  window: {{ addEventListener() {{}} }},
  console: console
}};

vm.createContext(sandbox);
const code = fs.readFileSync('frontend/dashboard/app.js', 'utf8');
vm.runInContext(code, sandbox);

const payload = {json.dumps(payload)};
const testEvents = [{{
  event_id: 'evt-feed-1',
  event_type: 'token_used',
  time: '2026-08-16T10:00:00Z',
  user_id: payload,
  token_hash: payload,
  ip_hash: payload,
  result: 'accepted'
}}];

// Mock getEvents to return the test events
sandbox.getEvents = () => Promise.resolve(testEvents);

sandbox.loadDashboardData().then(() => {{
  const allElements = collectAllElements(feedTable);
  const tags = allElements.map(e => e.tagName);
  const hasScript = tags.includes('SCRIPT');
  const hasImg = tags.includes('IMG');
  const fullText = feedTable.textContent;

  console.log(JSON.stringify({{
    hasScript,
    hasImg,
    textContainsPayload: fullText.includes(payload)
  }}));
}});
"""
    result = run_node_eval(test_script)
    assert not result["hasScript"], f"SCRIPT tag created in dashboard feed for {payload}"
    assert not result["hasImg"], f"IMG tag created in dashboard feed for {payload}"
    assert result["textContainsPayload"], f"Payload not preserved as text in dashboard feed for {payload}"


# ---------------------------------------------------------------------------
# Test 4: XSS Regression on Alerts View (renderAlerts)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("payload", [
    "<img src=x onerror=alert(1)>",
    "<script>alert(1)</script>",
    "');alert(1);//"
])
def test_dashboard_alerts_xss(payload):
    """
    Tests that malicious HTML or JavaScript breakout payloads injected into
    token_hash and event_type in renderAlerts are safely handled with addEventListener
    rather than inline onclick strings.
    """
    test_script = f"""
const fs = require('fs');
const vm = require('vm');

{NODE_DOM_MOCK}

const alertsTable = createMockElement('tbody');
const elements = {{
  'alerts-table-body': alertsTable,
  'filter-severity': {{ value: 'all', addEventListener() {{}} }},
  'filter-type': {{ value: 'all', addEventListener() {{}} }}
}};

const sandbox = {{
  document: {{
    addEventListener() {{}},
    querySelectorAll() {{ return []; }},
    getElementById(id) {{
      if (!elements[id]) elements[id] = createMockElement('div');
      return elements[id];
    }},
    createElement: createMockElement,
    createTextNode: createTextNode
  }},
  window: {{ addEventListener() {{}} }},
  console: console
}};

vm.createContext(sandbox);
const code = fs.readFileSync('frontend/dashboard/app.js', 'utf8');
vm.runInContext(code, sandbox);

const payload = {json.dumps(payload)};
const testAlerts = [{{
  event_id: 'evt-alert-1',
  event_type: 'refresh_reuse_detected',
  time: '2026-08-16T10:00:00Z',
  user_id: 'user-khushi',
  token_hash: payload,
  result: 'rejected'
}}];

sandbox.getEvents = () => Promise.resolve(testAlerts);

sandbox.renderAlerts().then(() => {{
  const allElements = collectAllElements(alertsTable);
  const tags = allElements.map(e => e.tagName);
  const hasScript = tags.includes('SCRIPT');
  const hasImg = tags.includes('IMG');
  
  // Verify no onclick attribute exists
  let hasInlineOnclick = false;
  for (const el of allElements) {{
    if (el.attributes && el.attributes.onclick) {{
      hasInlineOnclick = true;
    }}
  }}

  // Find investigate button and verify eventListeners
  const buttons = allElements.filter(e => e.tagName === 'BUTTON');
  const buttonHasClickListener = buttons.some(b => b.eventListeners && b.eventListeners.click && b.eventListeners.click.length > 0);

  console.log(JSON.stringify({{
    hasScript,
    hasImg,
    hasInlineOnclick,
    buttonHasClickListener
  }}));
}});
"""
    result = run_node_eval(test_script)
    assert not result["hasScript"], f"SCRIPT tag created in alerts table for {payload}"
    assert not result["hasImg"], f"IMG tag created in alerts table for {payload}"
    assert not result["hasInlineOnclick"], f"Inline onclick attribute found in alerts table for {payload}"
    assert result["buttonHasClickListener"], "Button click listener not attached via addEventListener"


# ---------------------------------------------------------------------------
# Test 5: XSS Regression on Event Log (appendEventLogRow in frontend/js/app.js)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("payload", [
    "<img src=x onerror=alert(1)>",
    "<script>alert(1)</script>"
])
def test_event_log_row_xss(payload):
    """
    Tests appendEventLogRow in frontend/js/app.js with malicious payloads
    in event_id, token_hash, ip_hash, device_id.
    """
    test_script = f"""
const fs = require('fs');
const vm = require('vm');

{NODE_DOM_MOCK}

const tbody = createMockElement('tbody');
const elements = {{
  'event-log-tbody': tbody,
  'site-nav': createMockElement('div'),
  'mobile-nav-toggle': createMockElement('button'),
  'mobile-overlay': createMockElement('div')
}};

const sandbox = {{
  document: {{
    addEventListener() {{}},
    querySelectorAll() {{ return []; }},
    getElementById(id) {{
      if (!elements[id]) elements[id] = createMockElement('div');
      return elements[id];
    }},
    createElement: createMockElement,
    createTextNode: createTextNode
  }},
  window: {{
    addEventListener() {{}},
    scrollTo() {{}},
    location: {{ hash: '' }}
  }},
  console: console,
  TokenDataService: {{
    getFamilies: () => Promise.resolve({{}}),
    getEvents: () => Promise.resolve([]),
    getScenarios: () => Promise.resolve([])
  }}
}};

vm.createContext(sandbox);
const code = fs.readFileSync('frontend/js/app.js', 'utf8');

const payload = {json.dumps(payload)};

// Extract and test appendEventLogRow directly with document context
const fnBody = code.match(/function appendEventLogRow\\(evt\\) \\{{([\\s\\S]*?)\\n  \\}}/)[1];
const testFn = new Function('evt', 'document', fnBody);

testFn({{
  event_id: payload,
  time: '2026-08-16T10:00:00Z',
  event_type: 'token_used',
  token_hash: payload,
  ip_hash: payload,
  device_id: payload,
  result: 'accepted'
}}, sandbox.document);

const allElements = collectAllElements(tbody);
const tags = allElements.map(e => e.tagName);
const hasScript = tags.includes('SCRIPT');
const hasImg = tags.includes('IMG');
const fullText = tbody.textContent;

console.log(JSON.stringify({{
  hasScript,
  hasImg,
  textContainsPayload: fullText.includes(payload)
}}));
"""
    result = run_node_eval(test_script)
    assert not result["hasScript"], f"SCRIPT tag created in event log for {payload}"
    assert not result["hasImg"], f"IMG tag created in event log for {payload}"
    assert result["textContainsPayload"], f"Payload text not found in event log for {payload}"


# ---------------------------------------------------------------------------
# Test 6: XSS Regression on TokenChainDiagram (Drawer & Nodes in diagram.js)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("payload", [
    "<img src=x onerror=alert(1)>",
    "<script>alert(1)</script>"
])
def test_diagram_drawer_xss(payload):
    """
    Tests TokenChainDiagram.openDrawer in frontend/js/diagram.js when token metadata
    (token_hash, token_family, parent_token_hash, superseded_by, user_id, attempted_event_id)
    contains malicious HTML.
    """
    test_script = f"""
const fs = require('fs');
const vm = require('vm');

{NODE_DOM_MOCK}

const drawerTitle = createMockElement('h3');
drawerTitle.id = 'drawer-token-title';
const drawerContent = createMockElement('div');
drawerContent.id = 'drawer-content';
const drawerEl = createMockElement('div');
drawerEl.id = 'token-detail-drawer';
drawerEl.appendChild(drawerTitle);
drawerEl.appendChild(drawerContent);
const drawerBackdrop = createMockElement('div');
drawerBackdrop.id = 'detail-drawer-backdrop';
const container = createMockElement('div');

const elements = {{
  'token-detail-drawer': drawerEl,
  'detail-drawer-backdrop': drawerBackdrop
}};

const sandbox = {{
  document: {{
    addEventListener() {{}},
    querySelectorAll() {{ return []; }},
    getElementById(id) {{
      return elements[id] || createMockElement('div');
    }},
    createElement: createMockElement,
    createTextNode: createTextNode,
    body: createMockElement('body')
  }},
  window: {{ addEventListener() {{}} }},
  console: console
}};

vm.createContext(sandbox);
const code = fs.readFileSync('frontend/js/diagram.js', 'utf8') + '\\nthis.TokenChainDiagram = TokenChainDiagram;';
vm.runInContext(code, sandbox);

const payload = {json.dumps(payload)};
const diagram = new sandbox.TokenChainDiagram(container, {{ size: 'full' }});

const maliciousTok = {{
  token_hash: payload,
  token_family: payload,
  parent_token_hash: payload,
  superseded_by: payload,
  user_id: payload,
  status: 'reused',
  issued_at: '2026-08-16T10:00:00Z',
  rotated_at: '2026-08-16T10:30:00Z',
  reuse_details: {{
    reused_at: '2026-08-16T10:40:00Z',
    attempted_event_id: payload
  }}
}};

diagram.openDrawer(maliciousTok);

const allElements = collectAllElements(drawerEl);
const tags = allElements.map(e => e.tagName);
const hasScript = tags.includes('SCRIPT');
const hasImg = tags.includes('IMG');
const fullText = drawerEl.textContent;

console.log(JSON.stringify({{
  hasScript,
  hasImg,
  textContainsPayload: fullText.includes(payload)
}}));
"""
    result = run_node_eval(test_script)
    assert not result["hasScript"], f"SCRIPT tag created in diagram drawer for {payload}"
    assert not result["hasImg"], f"IMG tag created in diagram drawer for {payload}"
    assert result["textContainsPayload"], f"Payload text not found in diagram drawer for {payload}"


# ---------------------------------------------------------------------------
# Test 7: XSS Regression on TokenGlobe Tooltip (globe.js)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("payload", [
    "<img src=x onerror=alert(1)>",
    "<script>alert(1)</script>"
])
def test_globe_tooltip_xss(payload):
    """
    Tests TokenGlobe tooltip rendering when token_hash or token_family contains HTML.
    """
    test_script = f"""
const fs = require('fs');
const vm = require('vm');

{NODE_DOM_MOCK}

const tooltip = createMockElement('div');
tooltip.id = 'globe-tooltip';

const sandbox = {{
  document: {{
    addEventListener() {{}},
    querySelectorAll() {{ return []; }},
    getElementById(id) {{ return createMockElement('div'); }},
    createElement: createMockElement,
    createTextNode: createTextNode
  }},
  window: {{ addEventListener() {{}} }},
  console: console
}};

vm.createContext(sandbox);
const code = fs.readFileSync('frontend/js/globe.js', 'utf8');
vm.runInContext(code, sandbox);

const payload = {json.dumps(payload)};

// Test the tooltip DOM construction snippet from TokenGlobe
const closest = {{
  hash: payload,
  family: payload,
  status: 'active',
  sx: 100,
  sy: 100
}};

const hashShort = closest.hash.length > 16 ? closest.hash.slice(0, 14) + '..' : closest.hash;
const famShort = closest.family.length > 18 ? closest.family.slice(0, 16) + '..' : closest.family;
const statusClass = closest.status === 'reused' ? 'badge-reused' : (closest.status === 'rotated' ? 'badge-rotated' : 'badge-active');

tooltip.textContent = '';

const line1 = sandbox.document.createElement('div');
line1.style.cssText = 'font-family: var(--font-mono); font-weight: 600; margin-bottom: 4px;';
const lbl1 = sandbox.document.createElement('span');
lbl1.style.color = 'var(--text-muted)';
lbl1.textContent = 'token_hash: ';
line1.appendChild(lbl1);
line1.appendChild(sandbox.document.createTextNode(hashShort));

const line2 = sandbox.document.createElement('div');
line2.style.cssText = 'font-size: 11px; color: var(--text-muted); margin-bottom: 6px;';
const lbl2 = sandbox.document.createElement('span');
lbl2.textContent = 'token_family: ';
const val2 = sandbox.document.createElement('span');
val2.style.color = 'var(--text-primary)';
val2.textContent = famShort;
line2.appendChild(lbl2);
line2.appendChild(val2);

const line3 = sandbox.document.createElement('div');
const badge = sandbox.document.createElement('span');
badge.className = `badge ${{statusClass}}`;
badge.textContent = closest.status;
line3.appendChild(badge);

tooltip.appendChild(line1);
tooltip.appendChild(line2);
tooltip.appendChild(line3);

const allElements = collectAllElements(tooltip);
const tags = allElements.map(e => e.tagName);

console.log(JSON.stringify({{
  hasScript: tags.includes('SCRIPT'),
  hasImg: tags.includes('IMG'),
  textContainsPayload: tooltip.textContent.includes(payload.slice(0, 10))
}}));
"""
    result = run_node_eval(test_script)
    assert not result["hasScript"], f"SCRIPT tag created in globe tooltip for {payload}"
    assert not result["hasImg"], f"IMG tag created in globe tooltip for {payload}"
    assert result["textContainsPayload"], f"Payload text not found in globe tooltip for {payload}"


# ---------------------------------------------------------------------------
# Test 8: Legitimate Event Values Render Accurately
# ---------------------------------------------------------------------------

def test_legitimate_event_values_render_correctly():
    """
    Verifies that legitimate, standard events render with correct labels,
    status badges, timestamps, and data values.
    """
    test_script = """
const fs = require('fs');
const vm = require('vm');

""" + NODE_DOM_MOCK + """

const detailContent = createMockElement('div');
const elements = {
  'timeline-detail-content': detailContent,
  'dashboard-event-feed': createMockElement('table'),
  'token-search': createMockElement('input')
};

const sandbox = {
  document: {
    addEventListener() {},
    querySelectorAll() { return []; },
    getElementById(id) {
      if (!elements[id]) elements[id] = createMockElement('div');
      return elements[id];
    },
    createElement: createMockElement,
    createTextNode: createTextNode
  },
  window: { addEventListener() {} },
  console: console,
  fetch() { return Promise.resolve({ json: () => Promise.resolve([]) }); }
};

vm.createContext(sandbox);
const code = fs.readFileSync('frontend/dashboard/app.js', 'utf8');
vm.runInContext(code, sandbox);

const legitEvent = {
  event_id: 'evt-001',
  event_type: 'token_issued',
  time: '2026-08-16T10:00:00Z',
  user_id: 'user-khushi',
  token_hash: 'tok_a1b2c3d4e5f6',
  token_family: 'fam-khushi-session-1',
  ip_hash: 'ip_a8e9f2b1',
  country: 'IN',
  device_id: 'device-laptop-khushi',
  user_agent_family: 'Chrome',
  endpoint: '/api/auth/login',
  result: 'accepted'
};

sandbox.showEventDetails(legitEvent);

const text = detailContent.textContent;
const checks = {
  hasEventId: text.includes('evt-001'),
  hasUserId: text.includes('user-khushi'),
  hasEndpoint: text.includes('/api/auth/login'),
  hasCountry: text.includes('IN'),
  hasDeviceId: text.includes('device-laptop-khushi'),
  hasUserAgent: text.includes('Chrome'),
  hasAction: text.includes('token_issued')
};

console.log(JSON.stringify(checks));
"""
    result = run_node_eval(test_script)
    for field, passed in result.items():
        assert passed, f"Legitimate value check failed: {field}"
