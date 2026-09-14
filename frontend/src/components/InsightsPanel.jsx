import { useEffect, useState } from 'react';
import { api } from '../api';
import './InsightsPanel.css';

export default function InsightsPanel() {
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    api.insights().then(setData).catch((e) => setError(e.message));
  }, []);

  if (error) return <div className="batch-status batch-status--error">{error}</div>;
  if (!data) return <div className="batch-status">Loading model insights…</div>;

  const { metrics, top_features } = data;
  const maxImportance = Math.max(...top_features.map((f) => f.importance));
  const [tn, fp] = metrics.confusion_matrix[0];
  const [fn, tp] = metrics.confusion_matrix[1];
  const perClass = metrics.per_class || {};

  return (
    <div className="insights-panel">
      <div>
        <h3 className="insights-panel__heading">Held-out test metrics — intrusion vs normal</h3>
        <div className="metrics-grid">
          <Metric label="Accuracy" value={metrics.accuracy} />
          <Metric label="Precision" value={metrics.precision} />
          <Metric label="Recall" value={metrics.recall} />
          <Metric label="F1 score" value={metrics.f1} />
        </div>
      </div>

      <div>
        <h3 className="insights-panel__heading">Held-out test metrics — attack type (multiclass)</h3>
        <div className="metrics-grid">
          <Metric label="Accuracy" value={metrics.multiclass.accuracy} />
          <Metric label="Precision (macro)" value={metrics.multiclass.precision_macro} />
          <Metric label="Recall (macro)" value={metrics.multiclass.recall_macro} />
          <Metric label="F1 (macro)" value={metrics.multiclass.f1_macro} />
        </div>
      </div>

      <div>
        <h3 className="insights-panel__heading">Per attack-type performance</h3>
        <div className="batch-table-wrap">
          <table className="batch-table">
            <thead>
              <tr>
                <th>Class</th>
                <th>Precision</th>
                <th>Recall</th>
                <th>F1</th>
                <th>Support</th>
              </tr>
            </thead>
            <tbody>
              {Object.entries(perClass).map(([name, m]) => (
                <tr key={name} className={name === 'BENIGN' ? 'row--safe' : 'row--alert'}>
                  <td>{name}</td>
                  <td>{(m.precision * 100).toFixed(1)}%</td>
                  <td>{(m.recall * 100).toFixed(1)}%</td>
                  <td>{(m.f1 * 100).toFixed(1)}%</td>
                  <td>{m.support}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      <div>
        <h3 className="insights-panel__heading">Confusion matrix (intrusion vs normal)</h3>
        <div className="confusion-matrix">
          <div className="cm-cell cm-cell--head" />
          <div className="cm-cell cm-cell--head">Pred. normal</div>
          <div className="cm-cell cm-cell--head">Pred. intrusion</div>

          <div className="cm-cell cm-cell--head">Actual normal</div>
          <div className="cm-cell cm-cell--safe">{tn}</div>
          <div className="cm-cell cm-cell--warn">{fp}</div>

          <div className="cm-cell cm-cell--head">Actual intrusion</div>
          <div className="cm-cell cm-cell--warn">{fn}</div>
          <div className="cm-cell cm-cell--safe">{tp}</div>
        </div>
      </div>

      <div>
        <h3 className="insights-panel__heading">Top predictive features</h3>
        <div className="importance-list">
          {top_features.map((f) => (
            <div className="importance-row" key={f.feature}>
              <span className="importance-row__label">{f.feature}</span>
              <div className="importance-row__track">
                <div
                  className="importance-row__fill"
                  style={{ width: `${(f.importance / maxImportance) * 100}%` }}
                />
              </div>
              <span className="importance-row__value">{(f.importance * 100).toFixed(1)}%</span>
            </div>
          ))}
        </div>
      </div>

      {metrics.trained_on_synthetic_data && (
        <div className="insights-warning">
          This model was trained on synthetic demo data — these metrics look
          unrealistically perfect. Train on the real CICIDS2017 CSVs (see
          backend/data/README.md) for numbers you can trust.
        </div>
      )}
    </div>
  );
}

function Metric({ label, value }) {
  return (
    <div className="metric-card">
      <span className="metric-card__value">{(value * 100).toFixed(1)}%</span>
      <span className="metric-card__label">{label}</span>
    </div>
  );
}
