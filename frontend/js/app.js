/**
 * TokenLine - Main Application Controller
 * Handles SPA navigation, sticky header transitions, stages storytelling,
 * Live Demo scenario streaming with staggered playback, Family Browser, and Schema Docs.
 */
document.addEventListener('DOMContentLoaded', () => {
  // --- STATE ---
  let currentView = 'home';
  let globeInstance = null;
  let liveDemoDiagram = null;
  let previewDiagram = null;
  let stageDiagram = null;
  let allFamilies = {};
  let allEvents = [];
  let isStreaming = false;

  // --- DOM ELEMENTS ---
  const siteNav = document.getElementById('site-nav');
  const mobileToggle = document.getElementById('mobile-nav-toggle');
  const mobileOverlay = document.getElementById('mobile-overlay');
  const navLinks = document.querySelectorAll('.nav-link, .mobile-link');
  const viewSections = document.querySelectorAll('.view-page');

  // --- INITIALIZE ROUTING ---
  function handleRoute() {
    const hash = window.location.hash.replace('#', '') || 'home';
    const validViews = ['home', 'how-it-works', 'demo', 'families', 'docs', 'about'];
    
    currentView = validViews.includes(hash) ? hash : (hash.startsWith('family-') ? 'families' : '404');

    viewSections.forEach(section => {
      section.style.display = section.id === `view-${currentView}` ? 'block' : 'none';
    });

    navLinks.forEach(link => {
      const linkTarget = link.getAttribute('href').replace('#', '');
      link.classList.toggle('active', linkTarget === currentView);
    });

    if (mobileOverlay) mobileOverlay.classList.remove('open');
    window.scrollTo(0, 0);

    // View-specific initializations
    if (currentView === 'home') {
      initHomeView();
    } else if (currentView === 'how-it-works') {
      initStagesView();
    } else if (currentView === 'demo') {
      initDemoView();
    } else if (currentView === 'families') {
      initFamiliesView();
    } else if (currentView === 'docs') {
      initDocsView();
    }
  }

  window.addEventListener('hashchange', handleRoute);

  // --- STICKY NAV SCROLL LISTENER ---
  window.addEventListener('scroll', () => {
    if (window.scrollY > 40) {
      siteNav.classList.add('scrolled');
    } else {
      siteNav.classList.remove('scrolled');
    }
  });

  // --- MOBILE MENU TOGGLE ---
  if (mobileToggle && mobileOverlay) {
    mobileToggle.addEventListener('click', () => {
      mobileOverlay.classList.toggle('open');
    });
  }

  // --- 1. HOME VIEW (Globe + Preview) ---
  async function initHomeView() {
    allFamilies = await TokenDataService.getFamilies();
    allEvents = await TokenDataService.getEvents();

    // Setup Globe
    const globeCanvas = document.getElementById('hero-globe-canvas');
    const globeTooltip = document.getElementById('globe-tooltip');
    
    if (globeCanvas && !globeInstance) {
      globeInstance = new TokenGlobe(globeCanvas, globeTooltip, {
        onTokenClick: (tok) => {
          window.location.hash = '#families';
          setTimeout(() => {
            const familyCard = document.querySelector(`[data-family-id="${tok.token_family}"]`);
            if (familyCard) familyCard.click();
          }, 150);
        }
      });
    }

    // Prepare tokens and threads for Globe
    const globeTokens = [];
    const globeThreads = [];

    Object.entries(allFamilies).forEach(([famId, tokens]) => {
      tokens.forEach((tok, idx) => {
        globeTokens.push(tok);
        if (tok.parent_token_hash) {
          globeThreads.push({
            parent: tok.parent_token_hash,
            child: tok.token_hash,
            offset: (idx * 0.3) % 1
          });
        }
      });
    });

    if (globeInstance) {
      globeInstance.setData(globeTokens, globeThreads);
    }

    // Mini Live Preview Diagram
    const previewContainer = document.getElementById('home-preview-diagram');
    if (previewContainer && !previewDiagram) {
      previewDiagram = new TokenChainDiagram(previewContainer, { size: 'full' });
      const sampleFamily = allFamilies['family-khushi-1'] || Object.values(allFamilies)[0] || [];
      previewDiagram.render(sampleFamily, 'family-khushi-1');
    }
  }

  // --- 2. HOW IT WORKS / STAGES VIEW ---
  function initStagesView() {
    const stageCards = document.querySelectorAll('.stage-card');
    const stageContainer = document.getElementById('stage-diagram-container');
    const stageStepNum = document.getElementById('stage-step-indicator');

    if (stageContainer && !stageDiagram) {
      stageDiagram = new TokenChainDiagram(stageContainer, { size: 'full' });
    }

    const STAGE_DATA = {
      1: {
        num: '01 / 05',
        tokens: [{ token_hash: 'tok_stage_01', status: 'active', issued_at: '2026-08-16T10:00:00Z', user_id: 'alice' }]
      },
      2: {
        num: '02 / 05',
        tokens: [
          { token_hash: 'tok_parent_A', status: 'rotated', superseded_by: 'tok_child_B', user_id: 'alice' },
          { token_hash: 'tok_child_B', parent_token_hash: 'tok_parent_A', status: 'active', user_id: 'alice' }
        ]
      },
      3: {
        num: '03 / 05',
        tokens: [
          { token_hash: 'tok_parent_A', status: 'reused', superseded_by: 'tok_child_B', user_id: 'alice', reuse_details: { reused_at: '10:35:00Z', attempted_event_id: 'evt-alert' } },
          { token_hash: 'tok_child_B', parent_token_hash: 'tok_parent_A', status: 'active', user_id: 'alice' }
        ]
      },
      4: {
        num: '04 / 05',
        tokens: [
          { token_hash: 'tok_parent_A', status: 'reused', superseded_by: 'tok_child_B', user_id: 'alice' },
          { token_hash: 'tok_child_B', parent_token_hash: 'tok_parent_A', status: 'rotated', superseded_by: 'tok_child_C', user_id: 'alice' },
          { token_hash: 'tok_child_C', parent_token_hash: 'tok_child_B', status: 'active', user_id: 'alice' }
        ]
      },
      5: {
        num: '05 / 05',
        tokens: [
          { token_hash: 'tok_parent_A', status: 'rotated', superseded_by: 'tok_child_B', user_id: 'alice' },
          { token_hash: 'tok_child_B', parent_token_hash: 'tok_parent_A', status: 'rotated', superseded_by: 'tok_child_C', user_id: 'alice' },
          { token_hash: 'tok_child_C', parent_token_hash: 'tok_child_B', status: 'rotated', superseded_by: 'tok_child_D', user_id: 'alice' },
          { token_hash: 'tok_child_D', parent_token_hash: 'tok_child_C', status: 'active', user_id: 'alice' }
        ]
      }
    };

    function setStage(stageIndex) {
      stageCards.forEach((c, idx) => {
        c.classList.toggle('active', idx + 1 === stageIndex);
      });
      const data = STAGE_DATA[stageIndex] || STAGE_DATA[1];
      if (stageStepNum) stageStepNum.textContent = data.num;
      if (stageDiagram) stageDiagram.render(data.tokens, `stage-${stageIndex}`);
    }

    stageCards.forEach(card => {
      card.addEventListener('click', () => {
        const stageId = parseInt(card.getAttribute('data-stage'), 10);
        setStage(stageId);
      });
    });

    setStage(1);
  }

  // --- 3. LIVE DEMO VIEW ---
  async function initDemoView() {
    const demoDiagramContainer = document.getElementById('demo-diagram-container');
    const logTableBody = document.getElementById('event-log-tbody');
    const scenarioCardsContainer = document.getElementById('scenario-cards-container');

    if (demoDiagramContainer && !liveDemoDiagram) {
      liveDemoDiagram = new TokenChainDiagram(demoDiagramContainer, { size: 'full' });
    }

    const scenarios = await TokenDataService.getScenarios();
    if (scenarioCardsContainer) {
      scenarioCardsContainer.textContent = '';
      scenarios.forEach(sc => {
        const card = document.createElement('div');
        card.className = 'card scenario-card';
        card.setAttribute('data-scenario-id', sc.id);

        const inner = document.createElement('div');

        const eyebrow = document.createElement('div');
        eyebrow.className = 'eyebrow';
        eyebrow.textContent = (sc.id || '').toUpperCase();
        inner.appendChild(eyebrow);

        const title = document.createElement('h3');
        title.className = 'card-title';
        title.style.marginBottom = '8px';
        title.textContent = sc.name || '';
        inner.appendChild(title);

        const desc = document.createElement('p');
        desc.style.cssText = 'font-size: 0.875rem; color: var(--text-secondary); margin-bottom: 12px;';
        desc.textContent = sc.description || '';
        inner.appendChild(desc);

        const signalDiv = document.createElement('div');
        signalDiv.style.cssText = 'font-size: 0.75rem; color: var(--text-muted); font-family: var(--font-mono);';
        signalDiv.textContent = 'Signal: ';
        const signalSpan = document.createElement('span');
        signalSpan.style.color = 'var(--accent-cyan)';
        signalSpan.textContent = sc.detection_signal || '';
        signalDiv.appendChild(signalSpan);
        inner.appendChild(signalDiv);

        card.appendChild(inner);

        const btn = document.createElement('button');
        btn.className = 'btn btn-primary run-scenario-btn';
        btn.setAttribute('data-scenario', sc.id);
        btn.style.cssText = 'width: 100%; margin-top: 12px;';
        btn.textContent = 'Run Scenario';
        btn.addEventListener('click', async () => {
          if (isStreaming) return;
          await runScenarioStream(sc.id);
        });
        card.appendChild(btn);

        scenarioCardsContainer.appendChild(card);
      });
    }

    // Initial render of default scenario
    const defaultEvents = SCENARIO_FIXTURES['refresh-reuse'];
    renderEventLog(defaultEvents);
    updateDiagramFromEvents(defaultEvents);
  }

  async function runScenarioStream(scenarioId) {
    isStreaming = true;
    const runButtons = document.querySelectorAll('.run-scenario-btn');
    runButtons.forEach(b => b.disabled = true);

    const activeScenarioTitle = document.getElementById('active-scenario-name');
    if (activeScenarioTitle) activeScenarioTitle.textContent = scenarioId;

    const events = await TokenDataService.runScenario(scenarioId);
    const logTableBody = document.getElementById('event-log-tbody');
    if (logTableBody) logTableBody.textContent = '';

    const accumulatedEvents = [];

    // Stream events staggered one by one (400ms delay)
    for (let i = 0; i < events.length; i++) {
      const evt = events[i];
      accumulatedEvents.push(evt);

      // Append row to event log
      appendEventLogRow(evt);

      // Update Live Diagram
      updateDiagramFromEvents(accumulatedEvents);

      // Scroll event log to bottom
      const logWrap = document.querySelector('.log-table-wrap');
      if (logWrap) logWrap.scrollTop = logWrap.scrollHeight;

      await new Promise(r => setTimeout(r, 450));
    }

    isStreaming = false;
    runButtons.forEach(b => b.disabled = false);
  }

  function updateDiagramFromEvents(eventList) {
    if (!liveDemoDiagram) return;

    const tokenMap = new Map();
    const reuseRecords = [];

    eventList.forEach(evt => {
      const type = evt.event_type;
      const th = evt.token_hash;
      const parent = evt.parent_token_hash;
      const fam = evt.token_family || 'family-demo';

      if (type === 'token_issued') {
        tokenMap.set(th, {
          token_hash: th,
          token_family: fam,
          parent_token_hash: parent,
          status: 'active',
          issued_at: evt.time,
          user_id: evt.user_id
        });
      } else if (type === 'token_refreshed' && parent) {
        if (tokenMap.has(parent)) {
          const p = tokenMap.get(parent);
          p.status = 'rotated';
          p.rotated_at = evt.time;
          p.superseded_by = th;
        } else {
          tokenMap.set(parent, {
            token_hash: parent,
            token_family: fam,
            status: 'rotated',
            rotated_at: evt.time,
            superseded_by: th,
            user_id: evt.user_id
          });
        }
        tokenMap.set(th, {
          token_hash: th,
          token_family: fam,
          parent_token_hash: parent,
          status: 'active',
          issued_at: evt.time,
          user_id: evt.user_id
        });
      } else if (type === 'logout' || type === 'token_revoked') {
        if (tokenMap.has(th)) {
          tokenMap.get(th).status = 'revoked';
        }
      } else if (type === 'replay_detected' || evt.result === 'rejected') {
        // If rejected refresh or rotated token reuse
        const target = parent || th;
        if (tokenMap.has(target)) {
          const rec = tokenMap.get(target);
          if (rec.status === 'rotated') {
            rec.status = 'reused';
            rec.reuse_details = {
              reused_at: evt.time,
              attempted_event_id: evt.event_id
            };
          }
        }
      }
    });

    const tokenList = Array.from(tokenMap.values());
    liveDemoDiagram.render(tokenList, 'family-demo');
  }

  function renderEventLog(events) {
    const tbody = document.getElementById('event-log-tbody');
    if (!tbody) return;
    tbody.textContent = '';
    events.forEach(evt => appendEventLogRow(evt));
  }

  function appendEventLogRow(evt) {
    const tbody = document.getElementById('event-log-tbody');
    if (!tbody) return;

    const tr = document.createElement('tr');
    
    let typeBadge = 'badge-active';
    if (evt.event_type === 'token_refreshed') typeBadge = 'badge-rotated';
    if (evt.event_type && (evt.event_type.includes('reuse') || evt.event_type.includes('replay') || evt.result === 'rejected')) typeBadge = 'badge-reused';

    const timeShort = evt.time ? evt.time.split('T')[1].replace('Z', '') : '--:--:--';
    const hashShort = evt.token_hash && evt.token_hash.length > 14 ? evt.token_hash.slice(0, 14) + '..' : (evt.token_hash || '');

    // td 1: timestamp
    const tdTime = document.createElement('td');
    tdTime.className = 'timestamp mono';
    tdTime.textContent = timeShort;
    tr.appendChild(tdTime);

    // td 2: event_id
    const tdId = document.createElement('td');
    tdId.className = 'mono';
    tdId.textContent = evt.event_id || '';
    tr.appendChild(tdId);

    // td 3: event_type badge
    const tdType = document.createElement('td');
    const badge = document.createElement('span');
    badge.className = `badge ${typeBadge}`;
    badge.textContent = evt.event_type || '';
    tdType.appendChild(badge);
    tr.appendChild(tdType);

    // td 4: token_hash
    const tdHash = document.createElement('td');
    tdHash.className = 'mono hash';
    tdHash.textContent = hashShort;
    tr.appendChild(tdHash);

    // td 5: ip_hash
    const tdIp = document.createElement('td');
    tdIp.className = 'mono';
    tdIp.textContent = evt.ip_hash || '---';
    tr.appendChild(tdIp);

    // td 6: device_id
    const tdDev = document.createElement('td');
    tdDev.className = 'mono';
    tdDev.textContent = evt.device_id || '---';
    tr.appendChild(tdDev);

    // td 7: result
    const tdRes = document.createElement('td');
    const resSpan = document.createElement('span');
    resSpan.style.color = evt.result === 'accepted' ? 'var(--accent-cyan)' : 'var(--danger-red)';
    resSpan.style.fontFamily = 'var(--font-mono)';
    resSpan.style.fontWeight = '600';
    resSpan.textContent = evt.result || '';
    tdRes.appendChild(resSpan);
    tr.appendChild(tdRes);

    tbody.appendChild(tr);
  }

  // --- 4. FAMILY BROWSER VIEW ---
  async function initFamiliesView() {
    allFamilies = await TokenDataService.getFamilies();
    const familiesGrid = document.getElementById('families-grid');
    const searchInput = document.getElementById('family-search-input');
    const statusFilters = document.querySelectorAll('.filter-btn');

    let activeFilter = 'all';
    let searchQuery = '';

    function renderFilteredFamilies() {
      if (!familiesGrid) return;
      familiesGrid.textContent = '';

      const filtered = Object.entries(allFamilies).filter(([famId, tokens]) => {
        // Search query check
        const matchQuery = famId.toLowerCase().includes(searchQuery) ||
          tokens.some(t => t.token_hash.toLowerCase().includes(searchQuery));
        if (!matchQuery) return false;

        // Filter check
        if (activeFilter === 'all') return true;
        if (activeFilter === 'reused') return tokens.some(t => t.status === 'reused');
        if (activeFilter === 'active') return tokens.some(t => t.status === 'active');
        if (activeFilter === 'rotated') return tokens.some(t => t.status === 'rotated');
        return true;
      });

      if (filtered.length === 0) {
        familiesGrid.textContent = '';
        const emptyDiv = document.createElement('div');
        emptyDiv.style.cssText = 'grid-column: 1 / -1; padding: 48px; text-align: center; color: var(--text-muted);';
        emptyDiv.textContent = 'No token families matched the criteria.';
        familiesGrid.appendChild(emptyDiv);
        return;
      }

      filtered.forEach(([famId, tokens]) => {
        const card = document.createElement('div');
        card.className = 'card';
        card.setAttribute('data-family-id', famId);
        card.style.cursor = 'pointer';

        const newestToken = tokens[tokens.length - 1] || {};
        const hasReused = tokens.some(t => t.status === 'reused');
        const statusBadge = hasReused ? 'badge-reused' : (newestToken.status === 'rotated' ? 'badge-rotated' : 'badge-active');
        const statusText = hasReused ? 'REUSE DETECTED' : (newestToken.status || 'ACTIVE');

        const topRow = document.createElement('div');
        topRow.style.cssText = 'display: flex; align-items: center; justify-content: space-between; margin-bottom: 12px;';

        const famSpan = document.createElement('span');
        famSpan.className = 'mono';
        famSpan.style.cssText = 'font-weight: 700; color: var(--text-primary); font-size: 1rem;';
        famSpan.textContent = famId;
        topRow.appendChild(famSpan);

        const badgeSpan = document.createElement('span');
        badgeSpan.className = `badge ${statusBadge}`;
        badgeSpan.textContent = statusText;
        topRow.appendChild(badgeSpan);
        card.appendChild(topRow);

        const countRow = document.createElement('div');
        countRow.style.cssText = 'font-size: 0.8125rem; color: var(--text-muted); margin-bottom: 16px;';
        countRow.textContent = 'Tokens in family: ';
        const countSpan = document.createElement('span');
        countSpan.className = 'mono';
        countSpan.style.color = 'var(--text-primary)';
        countSpan.textContent = String(tokens.length);
        countRow.appendChild(countSpan);
        card.appendChild(countRow);

        const slot = document.createElement('div');
        slot.className = 'mini-diagram-slot';
        slot.style.pointerEvents = 'none';
        card.appendChild(slot);

        const miniDiagram = new TokenChainDiagram(slot, { size: 'small' });
        miniDiagram.render(tokens, famId);

        card.addEventListener('click', () => {
          // Open full detail view
          const detailModalContainer = document.getElementById('family-full-diagram-slot');
          const detailModalFamTitle = document.getElementById('modal-family-title');
          if (detailModalContainer) {
            const modalDiagram = new TokenChainDiagram(detailModalContainer, { size: 'full' });
            modalDiagram.render(tokens, famId);
          }
          if (detailModalFamTitle) detailModalFamTitle.textContent = famId;
          
          const modalBackdrop = document.getElementById('family-modal-backdrop');
          if (modalBackdrop) modalBackdrop.classList.add('open');
        });

        familiesGrid.appendChild(card);
      });
    }

    if (searchInput) {
      searchInput.addEventListener('input', (e) => {
        searchQuery = e.target.value.trim().toLowerCase();
        renderFilteredFamilies();
      });
    }

    statusFilters.forEach(btn => {
      btn.addEventListener('click', () => {
        statusFilters.forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        activeFilter = btn.getAttribute('data-filter');
        renderFilteredFamilies();
      });
    });

    // Close family modal
    const modalClose = document.getElementById('family-modal-close');
    const modalBackdrop = document.getElementById('family-modal-backdrop');
    if (modalClose && modalBackdrop) {
      modalClose.addEventListener('click', () => modalBackdrop.classList.remove('open'));
      modalBackdrop.addEventListener('click', (e) => {
        if (e.target === modalBackdrop) modalBackdrop.classList.remove('open');
      });
    }

    renderFilteredFamilies();
  }

  // --- 5. DOCS VIEW (Schema Table Auto-generator) ---
  function initDocsView() {
    const tableBody = document.getElementById('schema-fields-tbody');
    if (!tableBody) return;

    // Schema definition directly matching schema/event.schema.json
    const schemaFields = [
      { name: "event_id", type: "string", required: true, desc: "Unique event identifier (e.g. evt-001)" },
      { name: "event_type", type: "string (enum)", required: true, desc: "Lifecycle state: token_issued, token_used, token_refreshed, token_revoked, token_expired, logout, refresh_reuse_detected, suspicious_location, suspicious_device, replay_detected, login_failed, token_rejected" },
      { name: "time", type: "string (date-time)", required: true, desc: "ISO 8601 UTC timestamp of occurrence" },
      { name: "user_id", type: "string", required: true, desc: "Synthetic or application user identifier" },
      { name: "token_hash", type: "string", required: true, desc: "Privacy-preserving SHA-256 salted hash of the token" },
      { name: "token_family", type: "string", required: false, desc: "Stable lineage group ID shared by ancestor and child tokens" },
      { name: "parent_token_hash", type: "string", required: false, desc: "Token hash of the rotated predecessor token on refresh" },
      { name: "ip_hash", type: "string", required: true, desc: "Salted cryptographic hash of client IPv4/IPv6" },
      { name: "country", type: "string (ISO-3166)", required: false, desc: "2-letter uppercase ISO country code (e.g. US, IN)" },
      { name: "device_id", type: "string", required: true, desc: "Synthetic client hardware/session identifier" },
      { name: "user_agent_family", type: "string", required: false, desc: "Client browser / HTTP client family name" },
      { name: "endpoint", type: "string", required: false, desc: "Target application HTTP route" },
      { name: "result", type: "string (enum)", required: true, desc: "Outcome of request: accepted | rejected" }
    ];

    tableBody.textContent = '';
    schemaFields.forEach(f => {
      const tr = document.createElement('tr');

      const tdName = document.createElement('td');
      tdName.className = 'mono';
      tdName.style.cssText = 'color: var(--text-primary); font-weight: 600;';
      tdName.textContent = f.name;
      tr.appendChild(tdName);

      const tdType = document.createElement('td');
      tdType.className = 'mono';
      tdType.style.color = 'var(--accent-cyan)';
      tdType.textContent = f.type;
      tr.appendChild(tdType);

      const tdReq = document.createElement('td');
      const badge = document.createElement('span');
      badge.className = `badge ${f.required ? 'badge-reused' : 'badge-rotated'}`;
      badge.style.fontSize = '0.6875rem';
      badge.textContent = f.required ? 'Required' : 'Optional';
      tdReq.appendChild(badge);
      tr.appendChild(tdReq);

      const tdDesc = document.createElement('td');
      tdDesc.style.cssText = 'color: var(--text-secondary); font-size: 0.875rem;';
      tdDesc.textContent = f.desc;
      tr.appendChild(tdDesc);

      tableBody.appendChild(tr);
    });
  }

  // Initial trigger
  handleRoute();
});
