import { useEffect, useRef, useState } from 'react';
import { api } from '../api';
import FlowTrace from './FlowTrace';
import './LiveMonitor.css';

const MAX_FEED = 40;

export default function LiveMonitor() {
  const [status, setStatus] = useState(null);
  const [interfaces, setInterfaces] = useState([]);
  const [mode, setMode] = useState('simulate');
  const [iface, setIface] = useState('');
  const [feed, setFeed] = useState([]);
  const [connected, setConnected] = useState(false);
  const [error, setError] = useState(null);
  const wsRef = useRef(null);

  const refreshStatus = () => {
    api.liveStatus().then(setStatus).catch(() => {});
  };

  useEffect(() => {
    api.liveInterfaces().then((r) => setInterfaces(r.interfaces));
    refreshStatus();
    return () => wsRef.current?.close();
  }, []);

  const connectSocket = () => {
    if (wsRef.current) return;
    const ws = new WebSocket(api.liveSocketUrl());
    ws.onopen = () => setConnected(true);
    ws.onclose = () => {
      setConnected(false);
      wsRef.current = null;
    };
    ws.onerror = () => setConnected(false);
    ws.onmessage = (event) => {
      const payload = JSON.parse(event.data);
      setFeed((prev) => [payload, ...prev].slice(0, MAX_FEED));
      setStatus((prev) => ({ ...prev, running: true, stats: payload.stats }));
    };
    wsRef.current = ws;
  };

  const handleStart = async () => {
    setError(null);
    try {
      const res = await api.liveStart(mode, iface);
      setStatus(res);
      connectSocket();
    } catch (e) {
      setError(e.message);
    }
  };

  const handleStop = async () => {
    try {
      const res = await api.liveStop();
      setStatus(res);
    } catch (e) {
      setError(e.message);
    }
    wsRef.current?.close();
  };

  const running = status?.running;
  const latest = feed[0];
  const traceState = !running ? 'idle' : latest ? (latest.is_intrusion ? 'alert' : 'safe') : 'scanning';

  return (
    <div className="live-monitor">
      <p className="section-sub">
        Streams flows in real time and scores each one as it completes.{' '}
        <strong>Simulate mode</strong> generates realistic synthetic traffic
        and works anywhere.{' '}
        <strong>Capture mode</strong> sniffs real packets on a network
        interface — it needs <code>scapy</code> installed and, on Windows,{' '}
        <a href="https://npcap.com" target="_blank" rel="noreferrer">Npcap</a>{' '}
        plus running the backend as Administrator.
      </p>

      <FlowTrace state={traceState} />

      <div className="live-controls">
        <div className="live-controls__group">
          <label className="live-controls__label">Mode</label>
          <select value={mode} onChange={(e) => setMode(e.target.value)} disabled={running}>
            <option value="simulate">Simulate (no setup needed)</option>
            <option value="capture" disabled={!status?.scapy_available}>
              Capture (real packets)
            </option>
          </select>
        </div>

        {mode === 'capture' && (
          <div className="live-controls__group">
            <label className="live-controls__label">Interface</label>
            <select value={iface} onChange={(e) => setIface(e.target.value)} disabled={running}>
              <option value="">default</option>
              {interfaces.map((i) => (
                <option key={i} value={i}>
                  {i}
                </option>
              ))}
            </select>
          </div>
        )}

        {!running ? (
          <button className="analyze-btn live-controls__btn" onClick={handleStart}>
            START MONITORING
          </button>
        ) : (
          <button className="analyze-btn live-controls__btn live-controls__btn--stop" onClick={handleStop}>
            STOP
          </button>
        )}

        <span className={`live-dot ${connected ? 'live-dot--on' : ''}`} />
        <span className="live-controls__status">
          {running ? (connected ? 'streaming' : 'connecting…') : 'stopped'}
        </span>
      </div>

      {error && <div className="batch-status batch-status--error">{error}</div>}

      {status?.stats && (
        <div className="batch-summary">
          <div className="batch-summary__stat">
            <span className="batch-summary__value">{status.stats.total}</span>
            <span className="batch-summary__label">flows seen</span>
          </div>
          <div className="batch-summary__stat batch-summary__stat--alert">
            <span className="batch-summary__value">{status.stats.intrusions}</span>
            <span className="batch-summary__label">intrusions</span>
          </div>
          <div className="batch-summary__stat batch-summary__stat--safe">
            <span className="batch-summary__value">
              {status.stats.total ? Math.round((1 - status.stats.intrusions / status.stats.total) * 100) : 100}%
            </span>
            <span className="batch-summary__label">clean traffic</span>
          </div>
        </div>
      )}

      <div className="live-feed">
        {feed.length === 0 && (
          <div className="history-empty">
            {running ? 'Waiting for the first flow to complete…' : 'Start monitoring to see live flows here.'}
          </div>
        )}
        {feed.map((f, i) => (
          <div key={i} className={`live-feed__row ${f.is_intrusion ? 'live-feed__row--alert' : 'live-feed__row--safe'}`}>
            <span className="live-feed__time">{f.timestamp}</span>
            <span className="live-feed__verdict">{f.prediction}</span>
            {f.attack_type && f.attack_type !== 'BENIGN' && (
              <span className="live-feed__type">{f.attack_type}</span>
            )}
            <span className="live-feed__conf">{(f.confidence * 100).toFixed(1)}%</span>
          </div>
        ))}
      </div>
    </div>
  );
}
