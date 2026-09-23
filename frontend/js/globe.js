/**
 * TokenGlobe - 3D Wireframe Canvas Globe Visualization
 * Integrates precision spherical math (slerp great-circle arcs, FNV-1a deterministic hashing,
 * depth-blended lat/long wireframe grid, and traveling refresh-flow pulse particles).
 */
class TokenGlobe {
  constructor(canvasElement, tooltipElement, options = {}) {
    this.canvas = canvasElement;
    this.ctx = canvasElement.getContext('2d');
    this.tooltip = tooltipElement;
    this.stage = canvasElement.parentElement;
    this.onTokenClick = options.onTokenClick || (() => {});

    this.reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

    this.W = 0;
    this.H = 0;
    this.R = 0;
    this.DPR = 1;

    this.tokens = [];
    this.links = [];
    this.lastFrontTokens = [];

    // Interaction & Animation State
    this.rotationY = 0.6;
    this.rotationX = -0.25;
    this.autoSpeed = (2 * Math.PI) / 90; // one revolution per 90s in radians/sec
    this.dragging = false;
    this.lastX = 0;
    this.lastY = 0;
    this.idleTimer = null;
    this.userRotating = false;
    this.startTime = null;
    this.animationFrameId = null;

    this.PITCH_LIMIT = Math.PI / 2 - 0.05;
    this.LAT_STEP = 20;
    this.LON_STEP = 30;
    this.RING_SAMPLES = 48;

    this.init();
  }

  init() {
    this.resize();
    window.addEventListener('resize', () => this.resize());
    this.bindEvents();
    this.startLoop();
  }

  resize() {
    this.DPR = window.devicePixelRatio || 1;
    const rect = this.stage.getBoundingClientRect();
    this.W = rect.width || 520;
    this.H = rect.height || 520;
    this.canvas.width = this.W * this.DPR;
    this.canvas.height = this.H * this.DPR;
    this.ctx.setTransform(this.DPR, 0, 0, this.DPR, 0, 0);
    this.R = Math.min(this.W, this.H) * 0.40;
  }

  // FNV-1a 32-bit deterministic hash to [0, 1)
  hash01(str) {
    let h = 2166136261;
    for (let i = 0; i < str.length; i++) {
      h ^= str.charCodeAt(i);
      h = Math.imul(h, 16777619);
    }
    return ((h >>> 0) % 100000) / 100000;
  }

  statusColor(status) {
    if (status === 'reused') return '#FF3B3B';
    if (status === 'rotated') return '#F5A623';
    return '#35E0C6';
  }

  // 3D Spherical Math
  toXYZ(lat, lon) {
    const la = (lat * Math.PI) / 180;
    const lo = (lon * Math.PI) / 180;
    return {
      x: Math.cos(la) * Math.cos(lo),
      y: Math.sin(la),
      z: Math.cos(la) * Math.sin(lo)
    };
  }

  rotateY(p, theta) {
    const c = Math.cos(theta);
    const s = Math.sin(theta);
    return { x: p.x * c - p.z * s, y: p.y, z: p.x * s + p.z * c };
  }

  rotateX(p, phi) {
    const c = Math.cos(phi);
    const s = Math.sin(phi);
    return { x: p.x, y: p.y * c - p.z * s, z: p.y * s + p.z * c };
  }

  rotateFull(p, ry, rx) {
    return this.rotateX(this.rotateY(p, ry), rx);
  }

  project(p, radius) {
    return {
      sx: this.W / 2 + p.x * radius,
      sy: this.H / 2 - p.y * radius,
      z: p.z
    };
  }

  slerp(a, b, t) {
    const dot = Math.max(-1, Math.min(1, a.x * b.x + a.y * b.y + a.z * b.z));
    const omega = Math.acos(dot);
    if (omega < 1e-6) return a;
    const s = Math.sin(omega);
    const w1 = Math.sin((1 - t) * omega) / s;
    const w2 = Math.sin(t * omega) / s;
    return {
      x: a.x * w1 + b.x * w2,
      y: a.y * w1 + b.y * w2,
      z: a.z * w1 + b.z * w2
    };
  }

  setData(rawTokens, rawLinks = []) {
    this.tokens = rawTokens.map(t => {
      const h1 = this.hash01((t.token_hash || t.hash) + 'lat');
      const h2 = this.hash01((t.token_hash || t.hash) + 'lon');
      const lat = (h1 * 2 - 1) * 72; // avoid exact poles
      const lon = h2 * 360;
      return Object.assign({}, t, {
        hash: t.token_hash || t.hash,
        family: t.token_family || t.family || 'family-root',
        status: t.status || 'active',
        lat,
        lon
      });
    });

    const tokenMap = new Map(this.tokens.map(x => [x.hash, x]));

    this.links = [];
    rawLinks.forEach(l => {
      const fromTok = tokenMap.get(l.parent || l.from);
      const toTok = tokenMap.get(l.child || l.to);
      if (fromTok && toTok) {
        this.links.push({ from: fromTok, to: toTok });
      }
    });

    // If no links provided, auto-link tokens by parent_token_hash or family relationships
    if (this.links.length === 0) {
      this.tokens.forEach(t => {
        if (t.parent_token_hash && tokenMap.has(t.parent_token_hash)) {
          this.links.push({ from: tokenMap.get(t.parent_token_hash), to: t });
        }
      });
    }
  }

  bindEvents() {
    this.canvas.addEventListener('pointerdown', e => {
      this.dragging = true;
      this.lastX = e.clientX;
      this.lastY = e.clientY;
      this.userRotating = true;
      clearTimeout(this.idleTimer);
      if (this.canvas.setPointerCapture) {
        try { this.canvas.setPointerCapture(e.pointerId); } catch (_) {}
      }
    });

    this.canvas.addEventListener('pointermove', e => {
      if (this.dragging) {
        const dx = e.clientX - this.lastX;
        const dy = e.clientY - this.lastY;
        this.lastX = e.clientX;
        this.lastY = e.clientY;
        this.rotationY += dx * 0.007;
        this.rotationX = Math.max(-this.PITCH_LIMIT, Math.min(this.PITCH_LIMIT, this.rotationX - dy * 0.007));
      }
      this.handleHover(e);
    });

    window.addEventListener('pointerup', () => {
      if (!this.dragging && this.hoveredToken) {
        this.onTokenClick(this.hoveredToken);
      }
      this.dragging = false;
      clearTimeout(this.idleTimer);
      this.idleTimer = setTimeout(() => {
        this.userRotating = false;
      }, 4000);
    });

    this.canvas.addEventListener('pointerleave', () => {
      if (this.tooltip) this.tooltip.style.opacity = '0';
      this.hoveredToken = null;
    });
  }

  handleHover(e) {
    if (!this.tooltip) return;
    const rect = this.canvas.getBoundingClientRect();
    const mx = e.clientX - rect.left;
    const my = e.clientY - rect.top;
    let closest = null;
    let closestD = 18;

    this.lastFrontTokens.forEach(t => {
      const d = Math.hypot(t.sx - mx, t.sy - my);
      if (d < closestD) {
        closestD = d;
        closest = t;
      }
    });

    this.hoveredToken = closest;

    if (closest) {
      const hashShort = closest.hash.length > 16 ? closest.hash.slice(0, 14) + '..' : closest.hash;
      const famShort = closest.family.length > 18 ? closest.family.slice(0, 16) + '..' : closest.family;
      const statusClass = closest.status === 'reused' ? 'badge-reused' : (closest.status === 'rotated' ? 'badge-rotated' : 'badge-active');

      this.tooltip.innerHTML = `
        <div style="font-family: var(--font-mono); font-weight: 600; margin-bottom: 4px;">
          <span style="color: var(--text-muted);">token_hash:</span> ${hashShort}
        </div>
        <div style="font-size: 11px; color: var(--text-muted); margin-bottom: 6px;">
          <span>token_family:</span> <span style="color: var(--text-primary);">${famShort}</span>
        </div>
        <div>
          <span class="badge ${statusClass}">${closest.status}</span>
        </div>
      `;

      this.tooltip.style.left = `${closest.sx + 14}px`;
      this.tooltip.style.top = `${closest.sy + 10}px`;
      this.tooltip.style.opacity = '1';
      this.canvas.style.cursor = 'pointer';
    } else {
      this.tooltip.style.opacity = '0';
      this.canvas.style.cursor = 'grab';
    }
  }

  drawGrid(theta, phi) {
    this.ctx.save();

    // Latitude parallels
    for (let lat = -80; lat <= 80; lat += this.LAT_STEP) {
      let prev = null;
      for (let i = 0; i <= this.RING_SAMPLES; i++) {
        const lon = (360 / this.RING_SAMPLES) * i;
        const p = this.rotateFull(this.toXYZ(lat, lon), theta, phi);
        const pr = this.project(p, this.R);
        if (prev) {
          const alpha = 0.05 + 0.22 * ((pr.z + p.z) / 4 + 0.5);
          this.ctx.strokeStyle = `rgba(120, 140, 160, ${Math.max(0.03, alpha)})`;
          this.ctx.lineWidth = 1;
          this.ctx.beginPath();
          this.ctx.moveTo(prev.sx, prev.sy);
          this.ctx.lineTo(pr.sx, pr.sy);
          this.ctx.stroke();
        }
        prev = pr;
      }
    }

    // Longitude meridians
    for (let lon = 0; lon < 360; lon += this.LON_STEP) {
      let prev = null;
      for (let i = 0; i <= this.RING_SAMPLES; i++) {
        const lat = -90 + (180 / this.RING_SAMPLES) * i;
        const p = this.rotateFull(this.toXYZ(lat, lon), theta, phi);
        const pr = this.project(p, this.R);
        if (prev) {
          const alpha = 0.05 + 0.22 * ((pr.z + p.z) / 4 + 0.5);
          this.ctx.strokeStyle = `rgba(120, 140, 160, ${Math.max(0.03, alpha)})`;
          this.ctx.lineWidth = 1;
          this.ctx.beginPath();
          this.ctx.moveTo(prev.sx, prev.sy);
          this.ctx.lineTo(pr.sx, pr.sy);
          this.ctx.stroke();
        }
        prev = pr;
      }
    }

    // Outer limb circle
    this.ctx.strokeStyle = 'rgba(140, 160, 180, 0.35)';
    this.ctx.lineWidth = 1.5;
    this.ctx.beginPath();
    this.ctx.arc(this.W / 2, this.H / 2, this.R, 0, Math.PI * 2);
    this.ctx.stroke();

    this.ctx.restore();
  }

  drawLinks(theta, phi, t) {
    this.ctx.save();
    this.links.forEach(link => {
      const a = this.toXYZ(link.from.lat, link.from.lon);
      const b = this.toXYZ(link.to.lat, link.to.lon);
      const N = 40;
      const color = link.to.status === 'reused' ? '255, 59, 59' :
                    link.to.status === 'rotated' ? '245, 166, 35' : '53, 224, 198';
      const pts = [];

      for (let i = 0; i <= N; i++) {
        const s = this.slerp(a, b, i / N);
        // lift slightly off surface for clarity
        const lift = 1.015 + 0.02 * Math.sin((i / N) * Math.PI);
        const lifted = { x: s.x * lift, y: s.y * lift, z: s.z * lift };
        const rp = this.rotateFull(lifted, theta, phi);
        const pr = this.project(rp, this.R);
        pts.push(pr);
      }

      const isReused = link.to.status === 'reused';

      // Draw Arc Segment
      for (let i = 1; i < pts.length; i++) {
        const p0 = pts[i - 1];
        const p1 = pts[i];
        const front = (p0.z + p1.z) > -0.3;
        if (!front) continue;
        const alpha = isReused ? 0.85 : 0.5;
        this.ctx.strokeStyle = `rgba(${color}, ${alpha})`;
        this.ctx.lineWidth = isReused ? 2 : 1.4;
        this.ctx.beginPath();
        this.ctx.moveTo(p0.sx, p0.sy);
        this.ctx.lineTo(p1.sx, p1.sy);
        this.ctx.stroke();
      }

      // Traveling Refresh Flow Pulse
      if (!this.reduceMotion) {
        const travel = (t * 0.15) % 1;
        const idx = Math.floor(travel * N);
        const glow = pts[idx];
        if (glow && glow.z > -0.3) {
          this.ctx.fillStyle = `rgba(${color}, 0.95)`;
          this.ctx.beginPath();
          this.ctx.arc(glow.sx, glow.sy, isReused ? 3.2 : 2.4, 0, Math.PI * 2);
          this.ctx.fill();
        }
      }
    });
    this.ctx.restore();
  }

  drawTokens(theta, phi, t) {
    this.lastFrontTokens = [];
    const projected = this.tokens.map(tok => {
      const p = this.rotateFull(this.toXYZ(tok.lat, tok.lon), theta, phi);
      const pr = this.project(p, this.R * 1.0);
      return Object.assign({}, tok, pr);
    });

    projected.sort((a, b) => a.z - b.z); // Back to front

    projected.forEach(tok => {
      const front = tok.z > -0.15;
      const alpha = front ? (0.55 + 0.45 * Math.max(0, tok.z)) : 0.12;
      const color = this.statusColor(tok.status);
      const size = tok.status === 'reused' ? 4.6 : 3.6;

      // Pulsing ring for reused token
      if (tok.status === 'reused' && !this.reduceMotion) {
        const pulse = (Math.sin((t * 2 * Math.PI) / 1.4) + 1) / 2;
        this.ctx.beginPath();
        this.ctx.arc(tok.sx, tok.sy, size + 4 + pulse * 6, 0, Math.PI * 2);
        this.ctx.strokeStyle = `rgba(255, 59, 59, ${0.35 * (1 - pulse) * Math.max(alpha, 0.3)})`;
        this.ctx.lineWidth = 1.5;
        this.ctx.stroke();
      }

      this.ctx.beginPath();
      this.ctx.arc(tok.sx, tok.sy, size, 0, Math.PI * 2);
      this.ctx.globalAlpha = alpha;
      this.ctx.fillStyle = color;
      this.ctx.fill();
      this.ctx.globalAlpha = 1;

      if (front) {
        this.lastFrontTokens.push(tok);
      }
    });
  }

  startLoop() {
    const frame = (ts) => {
      if (this.startTime === null) this.startTime = ts;
      const t = (ts - this.startTime) / 1000;

      if (!this.userRotating && !this.dragging && !this.reduceMotion) {
        this.rotationY += this.autoSpeed / 60;
      }

      this.ctx.clearRect(0, 0, this.W, this.H);
      this.drawGrid(this.rotationY, this.rotationX);
      this.drawLinks(this.rotationY, this.rotationX, t);
      this.drawTokens(this.rotationY, this.rotationX, t);

      this.animationFrameId = requestAnimationFrame(frame);
    };

    this.animationFrameId = requestAnimationFrame(frame);
  }

  destroy() {
    if (this.animationFrameId) {
      cancelAnimationFrame(this.animationFrameId);
    }
  }
}
