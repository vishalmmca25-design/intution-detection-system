import FlowTrace from './FlowTrace';
import './VerdictPanel.css';

export default function VerdictPanel({ traceState, result, error, health }) {
  return (
    <aside className="verdict-panel">
      <FlowTrace state={traceState} />

      {error && (
        <div className="verdict-card verdict-card--error">
          <div className="verdict-card__eyebrow">REQUEST FAILED</div>
          <div className="verdict-card__msg">{error}</div>
        </div>
      )}

      {!error && !result && (
        <div className="verdict-card verdict-card--idle">
          <div className="verdict-card__eyebrow">AWAITING FLOW</div>
          <div className="verdict-card__msg">
            Fill in the flow record on the left, or load a sample, then run
            the analysis.
          </div>
        </div>
      )}

      {result && !error && (
        <div className={`verdict-card verdict-card--${result.is_intrusion ? 'alert' : 'safe'}`}>
          <div className="verdict-card__eyebrow">
            {result.is_intrusion ? 'THREAT DETECTED' : 'FLOW CLEARED'}
          </div>
          <div className="verdict-card__verdict">{result.prediction}</div>
          {result.is_intrusion && (
            <div className="verdict-card__attack-type">{result.attack_type}</div>
          )}
          <div className="verdict-card__confidence">
            {(result.confidence * 100).toFixed(1)}% confidence
          </div>

          <div className="prob-bars">
            {Object.entries(result.probabilities)
              .sort((a, b) => b[1] - a[1])
              .map(([className, value]) => (
                <ProbBar
                  key={className}
                  label={className}
                  value={value}
                  tone={className === 'BENIGN' ? 'safe' : 'alert'}
                />
              ))}
          </div>
        </div>
      )}

      <div className="model-card">
        <div className="model-card__row">
          <span>Model</span>
          <span>Random Forest (200 trees)</span>
        </div>
        <div className="model-card__row">
          <span>Trained on</span>
          <span>{health?.metrics?.trained_on_synthetic_data === false ? 'CICIDS2017' : 'demo / synthetic data'}</span>
        </div>
        {health?.metrics && (
          <>
            <div className="model-card__row">
              <span>Test accuracy</span>
              <span>{(health.metrics.accuracy * 100).toFixed(1)}%</span>
            </div>
            <div className="model-card__row">
              <span>F1 (attack class)</span>
              <span>{(health.metrics.f1 * 100).toFixed(1)}%</span>
            </div>
          </>
        )}
      </div>
    </aside>
  );
}

function ProbBar({ label, value, tone }) {
  const pct = Math.round(value * 100);
  return (
    <div className="prob-bar">
      <div className="prob-bar__label">
        <span>P({label})</span>
        <span>{pct}%</span>
      </div>
      <div className="prob-bar__track">
        <div className={`prob-bar__fill prob-bar__fill--${tone}`} style={{ width: `${pct}%` }} />
      </div>
    </div>
  );
}
