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

    this.container.innerHTML = '';
    const wrapper = document.createElement('div');
    wrapper.className = `chain-diagram-container ${this.size === 'small' ? 'chain-diagram-small' : ''}`;

    const chainWrap = document.createElement('div');
    chainWrap.className = 'chain-diagram';

    if (this.tokens.length === 0) {
      chainWrap.innerHTML = `<span style="color: var(--text-muted); font-size: 0.8125rem;">No tokens in family</span>`;
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

      node.innerHTML = `
        <div class="node-pill">
          <span class="node-icon">${statusIcon}</span>
          <span class="token-hash">${hashShort}</span>
        </div>
        ${this.size === 'full' ? `<span style="font-size: 0.6875rem; color: var(--text-muted); font-family: var(--font-mono);">${tok.status}</span>` : ''}
      `;

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
        edge.innerHTML = `→`;
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

    let reuseHtml = '';
    if (tok.status === 'reused' || tok.reuse_details) {
      const reusedAt = (tok.reuse_details && tok.reuse_details.reused_at) || tok.rotated_at || 'Recently';
      const evtId = (tok.reuse_details && tok.reuse_details.attempted_event_id) || 'N/A';
      reuseHtml = `
        <div style="background-color: rgba(255, 59, 59, 0.1); border: 1px solid rgba(255, 59, 59, 0.3); border-radius: var(--radius-md); padding: var(--space-4);">
          <div style="color: var(--danger-red); font-weight: 700; margin-bottom: 6px; display: flex; align-items: center; gap: 6px;">
            <span>⚠️</span> Token Reuse Detected
          </div>
          <div style="font-size: 0.8125rem; color: var(--text-secondary); line-height: 1.5;">
            This token was previously rotated, but was subsequently presented again in event <code class="mono">${evtId}</code> at <span class="timestamp">${reusedAt}</span>.
          </div>
        </div>
      `;
    }

    if (drawerContent) {
      drawerContent.innerHTML = `
        ${reuseHtml}
        <div class="drawer-field">
          <span class="drawer-field-label">Status</span>
          <div><span class="badge ${badgeClass}">${tok.status}</span></div>
        </div>
        <div class="drawer-field">
          <span class="drawer-field-label">Token Family</span>
          <span class="drawer-field-val mono">${tok.token_family || this.familyId}</span>
        </div>
        <div class="drawer-field">
          <span class="drawer-field-label">Parent Token Hash</span>
          <span class="drawer-field-val mono">${tok.parent_token_hash || 'None (Root Token)'}</span>
        </div>
        <div class="drawer-field">
          <span class="drawer-field-label">Superseded By (Child)</span>
          <span class="drawer-field-val mono">${tok.superseded_by || 'None (Active Leaf)'}</span>
        </div>
        <div class="drawer-field">
          <span class="drawer-field-label">User ID</span>
          <span class="drawer-field-val mono">${tok.user_id || 'synthetic-user'}</span>
        </div>
        <div class="drawer-field">
          <span class="drawer-field-label">Issued / Observed Time</span>
          <span class="drawer-field-val timestamp">${tok.issued_at || tok.time || 'N/A'}</span>
        </div>
        ${tok.rotated_at ? `
        <div class="drawer-field">
          <span class="drawer-field-label">Rotated At</span>
          <span class="drawer-field-val timestamp">${tok.rotated_at}</span>
        </div>` : ''}
      `;
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
