import { useEffect, useState } from 'react';
import { api } from '../api';
import './HistoryPanel.css';

export default function HistoryPanel({ refreshKey }) {
  const [history, setHistory] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const load = () => {
    setLoading(true);
    api
      .history()
      .then((res) => setHistory(res.history))
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  };

  useEffect(load, [refreshKey]);

  const handleClear = async () => {
    await api.clearHistory();
    setHistory([]);
  };

  return (
    <div className="history-panel">
      <div className="history-panel__toolbar">
        <p className="section-sub" style={{ margin: 0 }}>
          Every flow analyzed this session (server-side, resets on restart).
        </p>
        <button type="button" className="chip" onClick={load}>
          Refresh
        </button>
        {history.length > 0 && (
          <button type="button" className="chip chip--alert" onClick={handleClear}>
            Clear
          </button>
        )}
      </div>

      {loading && <div className="batch-status">Loading…</div>}
      {error && <div className="batch-status batch-status--error">{error}</div>}

      {!loading && !error && history.length === 0 && (
        <div className="history-empty">No flows analyzed yet this session.</div>
      )}

      {history.length > 0 && (
        <div className="batch-table-wrap">
          <table className="batch-table">
            <thead>
              <tr>
                <th>Time</th>
                <th>Source</th>
                <th>Verdict</th>
                <th>Attack type</th>
                <th>Confidence</th>
              </tr>
            </thead>
            <tbody>
              {history.map((h) => (
                <tr key={h.id} className={h.prediction === 'INTRUSION' ? 'row--alert' : 'row--safe'}>
                  <td>{h.timestamp.split(' ')[1]}</td>
                  <td>{h.source}</td>
                  <td>{h.prediction}</td>
                  <td>{h.attack_type}</td>
                  <td>{(h.confidence * 100).toFixed(1)}%</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
