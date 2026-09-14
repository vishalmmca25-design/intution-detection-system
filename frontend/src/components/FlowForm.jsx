import './FlowForm.css';

// Group the 24 model features into sections that mirror how a CICFlowMeter
// export is actually organized, so the form reads like a real flow record
// rather than an arbitrary list of number boxes.
const GROUPS = [
  {
    title: 'Timing',
    keys: ['Flow Duration', 'Flow IAT Mean', 'Flow IAT Std', 'Fwd IAT Mean', 'Bwd IAT Mean'],
  },
  {
    title: 'Packet volume',
    keys: [
      'Total Fwd Packets',
      'Total Backward Packets',
      'Total Length of Fwd Packets',
      'Total Length of Bwd Packets',
      'Subflow Fwd Bytes',
    ],
  },
  {
    title: 'Packet size',
    keys: [
      'Fwd Packet Length Max',
      'Fwd Packet Length Mean',
      'Bwd Packet Length Max',
      'Bwd Packet Length Mean',
      'Average Packet Size',
    ],
  },
  {
    title: 'Rate & ratio',
    keys: ['Flow Bytes/s', 'Flow Packets/s', 'Down/Up Ratio', 'Fwd Header Length', 'Bwd Header Length'],
  },
  {
    title: 'TCP flags',
    keys: ['Fwd PSH Flags', 'SYN Flag Count', 'RST Flag Count', 'PSH Flag Count', 'ACK Flag Count'],
  },
];

export default function FlowForm({ featureSchema, values, onChange, onLoadSample, onSubmit, loading }) {
  const byKey = Object.fromEntries(featureSchema.map((f) => [f.key, f]));

  return (
    <form
      className="flow-form"
      onSubmit={(e) => {
        e.preventDefault();
        onSubmit();
      }}
    >
      <div className="flow-form__toolbar">
        <span className="flow-form__toolbar-label">Quick fill</span>
        <button type="button" className="chip chip--safe" onClick={() => onLoadSample('benign')}>
          Load benign sample
        </button>
        <button type="button" className="chip chip--alert" onClick={() => onLoadSample('attack')}>
          Load attack sample
        </button>
      </div>

      {GROUPS.map((group) => (
        <details className="flow-group" key={group.title} open>
          <summary>
            <span className="flow-group__title">{group.title}</span>
            <span className="flow-group__count">{group.keys.length}</span>
          </summary>
          <div className="flow-group__grid">
            {group.keys.map((key) => {
              const field = byKey[key];
              if (!field) return null;
              return (
                <label className="field" key={key}>
                  <span className="field__label">
                    {field.label}
                    <span className="field__unit">{field.unit}</span>
                  </span>
                  <input
                    className="field__input"
                    type="number"
                    step="any"
                    value={values[key] ?? ''}
                    onChange={(e) => onChange(key, e.target.value)}
                    required
                  />
                </label>
              );
            })}
          </div>
        </details>
      ))}

      <button type="submit" className="analyze-btn" disabled={loading}>
        {loading ? 'ANALYZING…' : 'ANALYZE FLOW'}
      </button>
    </form>
  );
}
