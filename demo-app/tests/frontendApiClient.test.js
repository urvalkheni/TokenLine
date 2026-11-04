const fs = require('fs');
const path = require('path');
const vm = require('vm');

const source = fs.readFileSync(
  path.join(__dirname, '../../frontend/js/api-client.js'),
  'utf8',
);
const dataSource = fs.readFileSync(
  path.join(__dirname, '../../frontend/js/data.js'),
  'utf8',
);

function loadApi(fetch) {
  const values = new Map();
  const sessionStorage = {
    getItem: key => values.get(key) ?? null,
    setItem: (key, value) => values.set(key, value),
    removeItem: key => values.delete(key),
  };
  const window = {
    location: { origin: 'http://127.0.0.1:5000', href: 'http://127.0.0.1:5000/' },
    sessionStorage,
    fetch,
  };
  vm.runInNewContext(source, { window, URL, Headers });
  return { api: window.TokenLineApi, values };
}

function loadDataService(api) {
  const values = new Map();
  const sessionStorage = {
    getItem: key => values.get(key) ?? null,
    setItem: (key, value) => values.set(key, value),
  };
  const statusEvents = [];
  class CustomEvent {
    constructor(type, options) {
      this.type = type;
      this.detail = options.detail;
    }
  }
  const window = { dispatchEvent: event => statusEvents.push(event) };
  const context = vm.createContext({ window, sessionStorage, CustomEvent, TokenLineApi: api });
  vm.runInContext(dataSource, context);
  return { service: vm.runInContext('TokenDataService', context), statusEvents };
}

describe('shared frontend collector API client', () => {
  test('sends the configured read credential and returns live events', async () => {
    const fetch = jest.fn().mockResolvedValue({
      ok: true,
      json: async () => [{ event_id: 'evt-live-1' }],
    });
    const { api } = loadApi(fetch);
    api.configure({ baseUrl: 'http://127.0.0.1:5000', apiKey: 'read-secret' });

    await expect(api.getEvents()).resolves.toEqual([{ event_id: 'evt-live-1' }]);
    expect(fetch).toHaveBeenCalledWith(
      'http://127.0.0.1:5000/api/events?limit=100',
      expect.objectContaining({
        headers: expect.objectContaining({ get: expect.any(Function) }),
      }),
    );
    expect(fetch.mock.calls[0][1].headers.get('Authorization')).toBe('Bearer read-secret');
  });

  test('surfaces authentication failures instead of returning fixture data', async () => {
    const fetch = jest.fn().mockResolvedValue({
      ok: false,
      status: 401,
      json: async () => ({ code: 'unauthorized', message: 'Unauthorized' }),
    });
    const { api } = loadApi(fetch);

    await expect(api.getEvents()).rejects.toMatchObject({
      status: 401,
      message: expect.stringContaining('read-capable API key'),
    });
  });

  test('reports an unavailable collector as a connection error', async () => {
    const { api } = loadApi(jest.fn().mockRejectedValue(new TypeError('fetch failed')));

    await expect(api.getEvents()).rejects.toMatchObject({
      status: 0,
      code: 'collector_unavailable',
      message: expect.stringContaining('Collector is unavailable'),
    });
  });

  test('uses fixture events only when demo mode is explicitly selected', async () => {
    const api = { getEvents: jest.fn().mockResolvedValue([{ event_id: 'evt-live-2' }]) };
    const { service, statusEvents } = loadDataService(api);
    service.setMode('demo');
    const demoEvents = await service.getEvents();

    expect(demoEvents.length).toBeGreaterThan(0);
    expect(api.getEvents).not.toHaveBeenCalled();
    expect(statusEvents.at(-1).detail.state).toBe('demo');
  });

  test('keeps an empty live response empty and marks the collector connected', async () => {
    const api = { getEvents: jest.fn().mockResolvedValue([]) };
    const { service, statusEvents } = loadDataService(api);
    service.setMode('live');

    await expect(service.getEvents()).resolves.toEqual([]);
    expect(statusEvents.at(-1).detail.state).toBe('healthy');
  });

  test('does not replace failed live requests with demo fixtures', async () => {
    const authError = Object.assign(new Error('Authentication required'), { status: 401 });
    const api = { getEvents: jest.fn().mockRejectedValue(authError) };
    const { service, statusEvents } = loadDataService(api);
    service.setMode('live');

    await expect(service.getEvents()).rejects.toBe(authError);
    expect(api.getEvents).toHaveBeenCalledTimes(1);
    expect(statusEvents.at(-1).detail.state).toBe('auth');
  });
});
