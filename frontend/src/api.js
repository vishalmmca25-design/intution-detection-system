// In local dev, Vite's proxy (see vite.config.js) forwards relative "/api"
// and "/ws" requests to the FastAPI server on :5000, so no env var is
// needed. In production (e.g. deployed on Vercel), there's no such proxy —
// the frontend is just static files — so it needs the *actual* URL of
// wherever the backend is deployed. Set that via a build-time env var:
//
//   VITE_API_BASE=https://your-backend.onrender.com
//
// (set this in Vercel: Project Settings → Environment Variables, then
// redeploy — Vite bakes it in at build time, it can't be changed at runtime)
const API_BASE = import.meta.env.VITE_API_BASE
  ? `${import.meta.env.VITE_API_BASE.replace(/\/$/, '')}/api`
  : '/api';

async function handle(res) {
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw new Error(data.detail || data.error || `Request failed (${res.status})`);
  }
  return data;
}

export const api = {
  health: () => fetch(`${API_BASE}/health`).then(handle),
  features: () => fetch(`${API_BASE}/features`).then(handle),
  samples: () => fetch(`${API_BASE}/samples`).then(handle),
  predict: (features) =>
    fetch(`${API_BASE}/predict`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ features }),
    }).then(handle),
  predictCsv: (file) => {
    const formData = new FormData();
    formData.append('file', file);
    return fetch(`${API_BASE}/predict/csv`, { method: 'POST', body: formData }).then(handle);
  },
  insights: () => fetch(`${API_BASE}/insights`).then(handle),
  history: () => fetch(`${API_BASE}/history`).then(handle),
  clearHistory: () => fetch(`${API_BASE}/history`, { method: 'DELETE' }).then(handle),
  liveInterfaces: () => fetch(`${API_BASE}/live/interfaces`).then(handle),
  liveStatus: () => fetch(`${API_BASE}/live/status`).then(handle),
  liveStart: (mode, iface) =>
    fetch(`${API_BASE}/live/start`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mode, interface: iface || null }),
    }).then(handle),
  liveStop: () => fetch(`${API_BASE}/live/stop`, { method: 'POST' }).then(handle),
  liveSocketUrl: () => {
    if (import.meta.env.VITE_API_BASE) {
      // e.g. "https://your-backend.onrender.com" -> "wss://your-backend.onrender.com/ws/live"
      const wsBase = import.meta.env.VITE_API_BASE.replace(/^http/, 'ws').replace(/\/$/, '');
      return `${wsBase}/ws/live`;
    }
    const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    return `${proto}//${window.location.host}/ws/live`;
  },
};
