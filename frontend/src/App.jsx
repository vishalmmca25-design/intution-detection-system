import { useEffect, useState } from 'react';
import { api } from './api';
import FlowForm from './components/FlowForm';
import VerdictPanel from './components/VerdictPanel';
import BatchUpload from './components/BatchUpload';
import HistoryPanel from './components/HistoryPanel';
import InsightsPanel from './components/InsightsPanel';
import LiveMonitor from './components/LiveMonitor';
import './App.css';

const TABS = [
  { id: 'single', label: 'Flow Inspector' },
  { id: 'live', label: 'Live Monitor' },
  { id: 'batch', label: 'Batch Upload' },
  { id: 'history', label: 'History' },
  { id: 'insights', label: 'Model Insights' },
];

export default function App() {
  const [tab, setTab] = useState('single');
  const [featureSchema, setFeatureSchema] = useState([]);
  const [samples, setSamples] = useState(null);
  const [values, setValues] = useState({});
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(false);
  const [health, setHealth] = useState(null);
  const [bootError, setBootError] = useState(null);
  const [traceState, setTraceState] = useState('idle');
  const [historyRefreshKey, setHistoryRefreshKey] = useState(0);

  useEffect(() => {
    Promise.all([api.features(), api.samples(), api.health()])
      .then(([featuresRes, samplesRes, healthRes]) => {
        setFeatureSchema(featuresRes.features);
        setSamples(samplesRes);
        setHealth(healthRes);
        setValues(samplesRes.benign);
      })
      .catch((e) => setBootError(e.message));
  }, []);

  const handleChange = (key, val) => {
    setValues((v) => ({ ...v, [key]: val }));
  };

  const handleLoadSample = (kind) => {
    if (!samples) return;
    setValues(samples[kind]);
    setResult(null);
    setError(null);
    setTraceState('idle');
  };

  const handleSubmit = async () => {
    setLoading(true);
    setError(null);
    setTraceState('scanning');
    try {
      const numericValues = Object.fromEntries(
        Object.entries(values).map(([k, v]) => [k, Number(v)])
      );
      const [res] = await Promise.all([
        api.predict(numericValues),
        new Promise((r) => setTimeout(r, 550)),
      ]);
      setResult(res);
      setTraceState(res.is_intrusion ? 'alert' : 'safe');
      setHistoryRefreshKey((k) => k + 1);
    } catch (e) {
      setError(e.message);
      setResult(null);
      setTraceState('idle');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="app">
      <div className="bg-grid" />
      <header className="app__header">
        <div className="app__brand">
          <span className="app__brand-mark">◆</span>
          <span className="app__brand-name">FLOWGUARD</span>
        </div>
        <div className="app__subtitle">
          flow-based intrusion detector — FastAPI + CICIDS2017
        </div>
        <div className={`app__status app__status--${health ? 'ok' : bootError ? 'down' : 'pending'}`}>
          <span className="app__status-dot" />
          {health ? 'model online' : bootError ? 'backend unreachable' : 'connecting…'}
        </div>
      </header>

      {bootError && (
        <div className="boot-error">
          Couldn't reach the backend at <code>/api</code> — {bootError}. Make
          sure the FastAPI server is running (<code>python app.py</code>) and
          a model has been trained (<code>python train_model.py</code>).
        </div>
      )}

      {!bootError && (
        <>
          <nav className="tabs">
            {TABS.map((t) => (
              <button
                key={t.id}
                className={`tabs__btn ${tab === t.id ? 'tabs__btn--active' : ''}`}
                onClick={() => setTab(t.id)}
              >
                {t.label}
              </button>
            ))}
          </nav>

          {tab === 'single' && (
            <main className="app__main">
              <section className="app__form-col">
                <h2 className="section-title">Flow Inspector</h2>
                <p className="section-sub">
                  Enter a network flow's CICFlowMeter-style statistics below,
                  or load a sample, then run the model against it.
                </p>
                {featureSchema.length > 0 ? (
                  <FlowForm
                    featureSchema={featureSchema}
                    values={values}
                    onChange={handleChange}
                    onLoadSample={handleLoadSample}
                    onSubmit={handleSubmit}
                    loading={loading}
                  />
                ) : (
                  <div className="loading-text">loading feature schema…</div>
                )}
              </section>

              <section className="app__verdict-col">
                <VerdictPanel traceState={traceState} result={result} error={error} health={health} />
              </section>
            </main>
          )}

          {tab === 'live' && (
            <main className="app__single-col">
              <h2 className="section-title">Live Monitor</h2>
              <LiveMonitor />
            </main>
          )}

          {tab === 'batch' && (
            <main className="app__single-col">
              <h2 className="section-title">Batch Upload</h2>
              <BatchUpload onAnalyzed={() => setHistoryRefreshKey((k) => k + 1)} />
            </main>
          )}

          {tab === 'history' && (
            <main className="app__single-col">
              <h2 className="section-title">Prediction History</h2>
              <HistoryPanel refreshKey={historyRefreshKey} />
            </main>
          )}

          {tab === 'insights' && (
            <main className="app__single-col">
              <h2 className="section-title">Model Insights</h2>
              <InsightsPanel />
            </main>
          )}
        </>
      )}

      <footer className="app__footer">
        Demo tool — not a substitute for a production IDS. Retrain on the
        real CICIDS2017 CSVs for a trustworthy model.
      </footer>
    </div>
  );
}
