/**
 * TokenChainDiagram - Directional Token-Family Rotation Lineage Visualizer
 * Renders complete parent->child chains (A -> B -> C) with distinct semantic states:
 * Active (Cyan), Rotated (Amber), and Reused (Red pulsing alert).
 */
class TokenChainDiagram {
  constructor(containerElement, options = {}) {
    this.container = containerElement;
    this.size = options.size || 'full'; // 'small' | 'full'
    this.onNodeClick = options.onNodeClick || null;
    this.tokens = [];
    this.familyId = null;
    this.drawerBackdrop = null;
    this.drawerElement = null;

    this.initDrawer();
  }

  initDrawer() {
    // Look for existing detail drawer elements or create if needed
    this.drawerBackdrop = document.getElementById('detail-drawer-backdrop');
    this.drawerElement = document.getElementById('token-detail-drawer');

    if (this.drawerBackdrop && this.drawerElement) {
      this.drawerBackdrop.addEventListener('click', () => this.closeDrawer());
      const closeBtn = this.drawerElement.querySelector('.drawer-close-btn');
      if (closeBtn) {
        closeBtn.addEventListener('click', () => this.closeDrawer());
      }
      window.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') this.closeDrawer();
      });
    }
  }

  /**
   * Sets data and renders the family chain.
   * @param {Array<Object>} tokens - Array of token records
   * @param {string} familyId - Token family identifier
   */
  render(tokens, familyId = 'family-root') {
    this.tokens = tokens || [];
    this.familyId = familyId;

    this.container.textContent = '';
    const wrapper = document.createElement('div');
    wrapper.className = `chain-diagram-container ${this.size === 'small' ? 'chain-diagram-small' : ''}`;

    const chainWrap = document.createElement('div');
    chainWrap.className = 'chain-diagram';

    if (this.tokens.length === 0) {
      const emptySpan = document.createElement('span');
      emptySpan.style.cssText = 'color: var(--text-muted); font-size: 0.8125rem;';
      emptySpan.textContent = 'No tokens in family';
      chainWrap.appendChild(emptySpan);
      wrapper.appendChild(chainWrap);
      this.container.appendChild(wrapper);
      return;
    }

    // Reconstruct ordered chain: find roots then walk forward
    const orderedTokens = this.orderTokens(this.tokens);

    orderedTokens.forEach((tok, idx) => {
      // 1. Create Node Element
      const node = document.createElement('div');
      const statusClass = tok.status === 'reused' ? 'state-reused' : (tok.status === 'rotated' ? 'state-rotated' : 'state-active');
      node.className = `chain-node ${statusClass}`;
      node.setAttribute('data-token-hash', tok.token_hash);
      node.setAttribute('tabindex', '0');
      node.setAttribute('role', 'button');
      node.setAttribute('aria-label', `Token ${tok.token_hash} - ${tok.status}`);

      const hashShort = tok.token_hash.length > 12 ? tok.token_hash.slice(0, 10) + '..' : tok.token_hash;
      const statusIcon = tok.status === 'reused' ? '!' : (tok.status === 'rotated' ? '↻' : '✓');

      node.textContent = '';
      const pill = document.createElement('div');
      pill.className = 'node-pill';

      const iconSpan = document.createElement('span');
      iconSpan.className = 'node-icon';
      iconSpan.textContent = statusIcon;

      const hashSpan = document.createElement('span');
      hashSpan.className = 'token-hash';
      hashSpan.textContent = hashShort;

      pill.appendChild(iconSpan);
      pill.appendChild(hashSpan);
      node.appendChild(pill);

      if (this.size === 'full') {
        const statusSpan = document.createElement('span');
        statusSpan.style.cssText = 'font-size: 0.6875rem; color: var(--text-muted); font-family: var(--font-mono);';
        statusSpan.textContent = tok.status || '';
        node.appendChild(statusSpan);
      }

      // Node interaction
      node.addEventListener('click', () => {
        if (this.onNodeClick) {
          this.onNodeClick(tok);
        } else {
          this.openDrawer(tok);
        }
      });

      node.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          node.click();
        }
      });

      chainWrap.appendChild(node);

      // 2. Create Connector Edge to next token (if not last)
      if (idx < orderedTokens.length - 1) {
        const nextTok = orderedTokens[idx + 1];
        const isDangerEdge = nextTok.status === 'reused' || tok.status === 'reused';
        const edge = document.createElement('div');
        edge.className = `chain-edge ${isDangerEdge ? 'edge-danger' : ''}`;
        edge.textContent = '→';
        chainWrap.appendChild(edge);
      }
    });

    wrapper.appendChild(chainWrap);
    this.container.appendChild(wrapper);
  }

  orderTokens(tokenList) {
    if (tokenList.length <= 1) return [...tokenList];

    const map = new Map(tokenList.map(t => [t.token_hash, t]));
    
    // Find root (token with no parent or whose parent is not in the list)
    let root = tokenList.find(t => !t.parent_token_hash || !map.has(t.parent_token_hash));
    if (!root) root = tokenList[0];

    const chain = [];
    const visited = new Set();
    let curr = root;

    while (curr && !visited.has(curr.token_hash)) {
      visited.add(curr.token_hash);
      chain.push(curr);

      // Find child: token whose parent_token_hash is curr.token_hash or curr.superseded_by
      let nextChild = tokenList.find(t => t.parent_token_hash === curr.token_hash && !visited.has(t.token_hash));
      if (!nextChild && curr.superseded_by) {
        nextChild = map.get(curr.superseded_by);
      }
      curr = nextChild;
    }

    // Append any orphaned or parallel tokens in family
    tokenList.forEach(t => {
      if (!visited.has(t.token_hash)) {
        chain.push(t);
      }
    });

    return chain;
  }

  openDrawer(tok) {
    if (!this.drawerElement || !this.drawerBackdrop) return;

    const drawerTitle = this.drawerElement.querySelector('#drawer-token-title');
    const drawerContent = this.drawerElement.querySelector('#drawer-content');

    if (drawerTitle) {
      drawerTitle.textContent = tok.token_hash;
    }

    const badgeClass = tok.status === 'reused' ? 'badge-reused' : (tok.status === 'rotated' ? 'badge-rotated' : 'badge-active');

    if (drawerContent) {
      drawerContent.textContent = '';

      if (tok.status === 'reused' || tok.reuse_details) {
        const reusedAt = (tok.reuse_details && tok.reuse_details.reused_at) || tok.rotated_at || 'Recently';
        const evtId = (tok.reuse_details && tok.reuse_details.attempted_event_id) || 'N/A';

        const alertBox = document.createElement('div');
        alertBox.style.cssText = 'background-color: rgba(255, 59, 59, 0.1); border: 1px solid rgba(255, 59, 59, 0.3); border-radius: var(--radius-md); padding: var(--space-4); margin-bottom: 16px;';

        const alertTitle = document.createElement('div');
        alertTitle.style.cssText = 'color: var(--danger-red); font-weight: 700; margin-bottom: 6px; display: flex; align-items: center; gap: 6px;';
        const warnIcon = document.createElement('span');
        warnIcon.textContent = '⚠️';
        alertTitle.appendChild(warnIcon);
        alertTitle.appendChild(document.createTextNode(' Token Reuse Detected'));
        alertBox.appendChild(alertTitle);

        const alertDesc = document.createElement('div');
        alertDesc.style.cssText = 'font-size: 0.8125rem; color: var(--text-secondary); line-height: 1.5;';
        alertDesc.appendChild(document.createTextNode('This token was previously rotated, but was subsequently presented again in event '));

        const evtCode = document.createElement('code');
        evtCode.className = 'mono';
        evtCode.textContent = evtId;
        alertDesc.appendChild(evtCode);

        alertDesc.appendChild(document.createTextNode(' at '));

        const timeSpan = document.createElement('span');
        timeSpan.className = 'timestamp';
        timeSpan.textContent = reusedAt;
        alertDesc.appendChild(timeSpan);

        alertDesc.appendChild(document.createTextNode('.'));
        alertBox.appendChild(alertDesc);

        drawerContent.appendChild(alertBox);
      }

      const addDrawerField = (label, value, valClass = 'mono', isBadge = false) => {
        const fieldDiv = document.createElement('div');
        fieldDiv.className = 'drawer-field';

        const labelSpan = document.createElement('span');
        labelSpan.className = 'drawer-field-label';
        labelSpan.textContent = label;
        fieldDiv.appendChild(labelSpan);

        if (isBadge) {
          const badgeWrap = document.createElement('div');
          const badge = document.createElement('span');
          badge.className = `badge ${badgeClass}`;
          badge.textContent = value || '';
          badgeWrap.appendChild(badge);
          fieldDiv.appendChild(badgeWrap);
        } else {
          const valSpan = document.createElement('span');
          valSpan.className = `drawer-field-val ${valClass}`;
          valSpan.textContent = value || '';
          fieldDiv.appendChild(valSpan);
        }

        drawerContent.appendChild(fieldDiv);
      };

      addDrawerField('Status', tok.status, '', true);
      addDrawerField('Token Family', tok.token_family || this.familyId);
      addDrawerField('Parent Token Hash', tok.parent_token_hash || 'None (Root Token)');
      addDrawerField('Superseded By (Child)', tok.superseded_by || 'None (Active Leaf)');
      addDrawerField('User ID', tok.user_id || 'synthetic-user');
      addDrawerField('Issued / Observed Time', tok.issued_at || tok.time || 'N/A', 'timestamp');

      if (tok.rotated_at) {
        addDrawerField('Rotated At', tok.rotated_at, 'timestamp');
      }
    }

    this.drawerBackdrop.classList.add('open');
    this.drawerElement.classList.add('open');
    document.body.style.overflow = 'hidden';
  }

  closeDrawer() {
    if (this.drawerElement && this.drawerBackdrop) {
      this.drawerBackdrop.classList.remove('open');
      this.drawerElement.classList.remove('open');
      document.body.style.overflow = '';
    }
  }
}
