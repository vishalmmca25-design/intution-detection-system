import { useRef, useState } from 'react';
import { api } from '../api';
import './BatchUpload.css';

export default function BatchUpload({ onAnalyzed }) {
  const [dragOver, setDragOver] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [result, setResult] = useState(null);
  const [fileName, setFileName] = useState(null);
  const inputRef = useRef(null);

  const handleFile = async (file) => {
    if (!file) return;
    setFileName(file.name);
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const res = await api.predictCsv(file);
      setResult(res);
      onAnalyzed?.();
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="batch-upload">
      <p className="section-sub">
        Upload a CSV with CICFlowMeter-style columns (same 24 fields as the
        form) to score many flows at once.
      </p>

      <div
        className={`dropzone ${dragOver ? 'dropzone--over' : ''}`}
        onDragOver={(e) => {
          e.preventDefault();
          setDragOver(true);
        }}
        onDragLeave={() => setDragOver(false)}
        onDrop={(e) => {
          e.preventDefault();
          setDragOver(false);
          handleFile(e.dataTransfer.files?.[0]);
        }}
        onClick={() => inputRef.current?.click()}
      >
        <input
          ref={inputRef}
          type="file"
          accept=".csv"
          hidden
          onChange={(e) => handleFile(e.target.files?.[0])}
        />
        <div className="dropzone__icon">⇪</div>
        <div className="dropzone__text">
          {fileName ? fileName : 'Drop a CSV here, or click to browse'}
        </div>
      </div>

      {loading && <div className="batch-status">Analyzing flows…</div>}
      {error && <div className="batch-status batch-status--error">{error}</div>}

      {result && (
        <div className="batch-results">
          <div className="batch-summary">
            <div className="batch-summary__stat">
              <span className="batch-summary__value">{result.summary.total}</span>
              <span className="batch-summary__label">flows analyzed</span>
            </div>
            <div className="batch-summary__stat batch-summary__stat--alert">
              <span className="batch-summary__value">{result.summary.intrusions}</span>
              <span className="batch-summary__label">flagged as intrusion</span>
            </div>
            <div className="batch-summary__stat batch-summary__stat--safe">
              <span className="batch-summary__value">{result.summary.normal}</span>
              <span className="batch-summary__label">normal</span>
            </div>
            {result.summary.skipped_invalid_rows > 0 && (
              <div className="batch-summary__stat">
                <span className="batch-summary__value">{result.summary.skipped_invalid_rows}</span>
                <span className="batch-summary__label">rows skipped (invalid)</span>
              </div>
            )}
          </div>

          <div className="batch-table-wrap">
            <table className="batch-table">
              <thead>
                <tr>
                  <th>#</th>
                  <th>Verdict</th>
                  <th>Attack type</th>
                  <th>Confidence</th>
                </tr>
              </thead>
              <tbody>
                {result.results.map((r, i) => (
                  <tr key={i} className={r.is_intrusion ? 'row--alert' : 'row--safe'}>
                    <td>{i + 1}</td>
                    <td>{r.prediction}</td>
                    <td>{r.attack_type}</td>
                    <td>{(r.confidence * 100).toFixed(1)}%</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
