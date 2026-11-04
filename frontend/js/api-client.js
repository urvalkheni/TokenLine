/** Shared authenticated client for the TokenLine Collector API. */
(function attachTokenLineApi(global) {
  const STORAGE_BASE = 'tokenline.collectorApiBase';
  const STORAGE_KEY = 'tokenline.collectorApiKey';

  class ApiError extends Error {
    constructor(status, code, message) {
      super(message);
      this.name = 'ApiError';
      this.status = status;
      this.code = code;
    }
  }

  function defaultBaseUrl() {
    if (global.location && global.location.origin && global.location.origin !== 'null') {
      return `${global.location.origin}/api`;
    }
    return 'http://127.0.0.1:5000/api';
  }

  function normalizeBaseUrl(value) {
    const url = new URL(value || defaultBaseUrl(), global.location?.href || 'http://127.0.0.1/');
    if (!['http:', 'https:'].includes(url.protocol)) {
      throw new Error('Collector URL must use HTTP or HTTPS.');
    }
    url.search = '';
    url.hash = '';
    url.pathname = url.pathname.replace(/\/+$/, '').replace(/\/api$/, '') + '/api';
    return url.toString().replace(/\/$/, '');
  }

  function getConfig() {
    const baseUrl = global.sessionStorage?.getItem(STORAGE_BASE) || defaultBaseUrl();
    return {
      baseUrl: normalizeBaseUrl(baseUrl),
      hasApiKey: Boolean(global.sessionStorage?.getItem(STORAGE_KEY)),
    };
  }

  function configure({ baseUrl, apiKey, clearApiKey = false } = {}) {
    const normalizedBase = normalizeBaseUrl(baseUrl || getConfig().baseUrl);
    global.sessionStorage?.setItem(STORAGE_BASE, normalizedBase);
    if (clearApiKey) {
      global.sessionStorage?.removeItem(STORAGE_KEY);
    } else if (typeof apiKey === 'string' && apiKey.trim()) {
      global.sessionStorage?.setItem(STORAGE_KEY, apiKey.trim());
    }
    return getConfig();
  }

  async function request(path, options = {}) {
    const config = getConfig();
    const headers = new Headers(options.headers || {});
    headers.set('Accept', 'application/json');
    const apiKey = global.sessionStorage?.getItem(STORAGE_KEY);
    if (apiKey) headers.set('Authorization', `Bearer ${apiKey}`);

    let response;
    try {
      response = await global.fetch(`${config.baseUrl}${path}`, { ...options, headers });
    } catch (error) {
      throw new ApiError(0, 'collector_unavailable', 'Collector is unavailable. Check the URL and network connection.');
    }

    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const message = response.status === 401
        ? 'Authentication required. Add a read-capable API key in Dashboard Settings.'
        : response.status === 403
          ? 'This API key does not have permission to read collector data.'
          : payload.message || `Collector request failed with status ${response.status}.`;
      throw new ApiError(response.status, payload.code || 'request_failed', message);
    }
    return payload;
  }

  global.TokenLineApi = Object.freeze({
    ApiError,
    configure,
    getConfig,
    request,
    getEvents: () => request('/events?limit=100'),
    getFamilies: () => request('/families'),
    getFamilyDetail: (familyId) => request(`/families/${encodeURIComponent(familyId)}`),
    getScenarios: () => request('/scenarios'),
    runScenario: (scenarioId) => request(`/scenarios/${encodeURIComponent(scenarioId)}/run`, { method: 'POST' }),
  });
})(window);
