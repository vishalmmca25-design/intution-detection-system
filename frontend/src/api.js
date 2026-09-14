const BASE = '/api';

async function handle(res) {
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw new Error(data.detail || data.error || `Request failed (${res.status})`);
  }
  return data;
}

export const api = {
  health: () => fetch(`${BASE}/health`).then(handle),
  features: () => fetch(`${BASE}/features`).then(handle),
  samples: () => fetch(`${BASE}/samples`).then(handle),
  predict: (features) =>
    fetch(`${BASE}/predict`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ features }),
    }).then(handle),
  predictCsv: (file) => {
    const formData = new FormData();
    formData.append('file', file);
    return fetch(`${BASE}/predict/csv`, { method: 'POST', body: formData }).then(handle);
  },
  insights: () => fetch(`${BASE}/insights`).then(handle),
  history: () => fetch(`${BASE}/history`).then(handle),
  clearHistory: () => fetch(`${BASE}/history`, { method: 'DELETE' }).then(handle),
  liveInterfaces: () => fetch(`${BASE}/live/interfaces`).then(handle),
  liveStatus: () => fetch(`${BASE}/live/status`).then(handle),
  liveStart: (mode, iface) =>
    fetch(`${BASE}/live/start`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mode, interface: iface || null }),
    }).then(handle),
  liveStop: () => fetch(`${BASE}/live/stop`, { method: 'POST' }).then(handle),
  liveSocketUrl: () => {
    const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    return `${proto}//${window.location.host}/ws/live`;
  },
};
