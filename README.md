# FlowGuard — CICIDS2017 Network Intrusion Detector

A full-stack demo: a Python/scikit-learn model trained on CICIDS2017 flow
data, a **FastAPI** backend that serves predictions (with auto-generated
Swagger docs at `/docs`), and a React frontend with five views: a live
traffic monitor, a single-flow inspector, batch CSV upload, a prediction
history log, and a model-insights dashboard (metrics, confusion matrix,
feature importances).

```
cicids-ids/
├── backend/
│   ├── features.py             # shared feature schema (24 CICIDS2017 columns)
│   ├── generate_sample_data.py # synthetic stand-in dataset (used if data/ is empty)
│   ├── train_model.py          # trains + evaluates + saves the model
│   ├── live_monitor.py         # live packet capture / flow tracking / feature extraction
│   ├── app.py                  # FastAPI app: predict, batch, csv upload, insights, history, live/ws
│   ├── requirements.txt
│   ├── data/                   # put the real CICIDS2017 CSVs here (see data/README.md)
│   └── model/                  # created by train_model.py (model.pkl, scaler.pkl, metadata.json)
└── frontend/
    ├── src/
    │   ├── App.jsx              # tabbed layout: Live / Flow Inspector / Batch / History / Insights
    │   ├── api.js
    │   └── components/          # FlowForm, VerdictPanel, FlowTrace, BatchUpload, HistoryPanel, InsightsPanel, LiveMonitor
    └── package.json
```

## 1. Get the real dataset (recommended)

This repo ships with a synthetic data generator so you can run the whole
pipeline immediately, but a model trained on synthetic data isn't something
you should trust. For a real model:

1. Download the CICIDS2017 CSVs ("MachineLearningCSV.zip") from
   https://www.unb.ca/cic/datasets/ids-2017.html
2. Unzip and drop the 8 CSV files into `backend/data/`
3. Re-run `python train_model.py` — it will use the real files automatically.

See `backend/data/README.md` for details.

## 2. Backend setup

```bash
cd backend
python -m venv venv && source venv/bin/activate   # optional but recommended
pip install -r requirements.txt

python train_model.py     # trains the model, prints metrics, saves to ./model/
python app.py              # starts the FastAPI server on http://localhost:5000
```

(`python app.py` runs uvicorn with `--reload` under the hood. You can also
run `uvicorn app:app --reload --port 5000` directly.)

Quick sanity check:

```bash
curl http://localhost:5000/api/health
```

Interactive API docs (try every endpoint from the browser, including file
upload): **http://localhost:5000/docs**

### API endpoints

| Method | Path | What it does |
|---|---|---|
| GET | `/api/health` | Model status + evaluation metrics |
| GET | `/api/features` | Feature schema (labels, units, example values) |
| GET | `/api/samples` | Example benign + attack flow payloads |
| POST | `/api/predict` | Score a single flow (`{"features": {...}}`) |
| POST | `/api/predict/batch` | Score a JSON array of flows |
| POST | `/api/predict/csv` | Score a CSV file of flows (multipart upload) |
| GET | `/api/insights` | Feature importances + confusion matrix |
| GET | `/api/history` | Last 50 predictions this server session |
| DELETE | `/api/history` | Clear the history log |
| GET | `/api/live/interfaces` | Network interfaces available for capture mode |
| GET | `/api/live/status` | Whether live monitoring is running + running stats |
| POST | `/api/live/start` | Start live monitoring (`{"mode": "simulate"\|"capture", "interface": "..."}`) |
| POST | `/api/live/stop` | Stop live monitoring |
| WS | `/ws/live` | Streams each newly-scored flow in real time while monitoring runs |

## 3. Frontend setup

In a second terminal:

```bash
cd frontend
npm install
npm run dev                # starts on http://localhost:5173
```

The dev server proxies `/api/*` to `http://127.0.0.1:5000` (see
`vite.config.js`), so just open http://localhost:5173 — no CORS setup
needed in dev (the FastAPI backend also allows all origins by default, so
it works even without the proxy).

Five tabs:
- **Live Monitor** — streams flows in real time over a WebSocket, scoring
  each one as it completes. **Simulate mode** works everywhere with no
  setup — it's the default. **Capture mode** sniffs real packets on a
  network interface using scapy; see "Live capture setup" below.
- **Flow Inspector** — fill in one flow's stats (or load a benign/attack
  sample) and get an instant verdict with a confidence breakdown.
- **Batch Upload** — drag in a CSV of many flows and get a per-row verdict
  table plus an intrusion/normal summary.
- **History** — every prediction made this server session (manual, batch,
  csv, or live), newest first.
- **Model Insights** — held-out test accuracy/precision/recall/F1/ROC-AUC,
  a confusion matrix, and the top predictive features.

For a production build: `npm run build` outputs static files to
`frontend/dist/` that you can serve from any static host — just make sure
`/api` and `/ws` are proxied (nginx, etc.) to wherever `app.py` is
deployed, or update `src/api.js`'s `BASE`/`liveSocketUrl` to point at your
API's full URL.

## 4. Live capture setup (optional — simulate mode needs none of this)

Real packet capture needs raw-socket access, which means OS-level
permissions:

**Windows**
1. Install [Npcap](https://npcap.com) (check "Install Npcap in WinPcap
   API-compatible mode" during setup).
2. Run PowerShell **as Administrator**, then `python app.py` from there.
3. In the Live Monitor tab, switch Mode to "Capture", pick an interface,
   and click Start.

**macOS / Linux**
```bash
sudo venv/bin/python app.py
```
(raw sockets need root; running the venv's Python directly with `sudo`
keeps your installed packages.)

If `scapy` isn't installed, or you don't have permission to open a raw
socket, capture mode will fail with a clear error — simulate mode requires
neither and always works, so it's the default.

**How live flow features are computed:** `live_monitor.py` groups packets
into flows by 5-tuple (src/dst IP, src/dst port, protocol), closes a flow
after ~2 seconds of inactivity, and computes the same 24 features the
model was trained on (durations, packet/byte counts, inter-arrival times,
TCP flag counts, etc.) before scoring it. This is a simplified, best-effort
approximation of CICFlowMeter — good enough for a live demo, not a
byte-for-byte match with offline CICFlowMeter exports.

## How the model works

- **Task**: multiclass classification — predicts `BENIGN` or the specific
  attack type (`DoS Hulk`, `DDoS`, `PortScan`, `FTP-Patator`, `Bot`, ...)
  rather than just a yes/no. The API also derives a simple `is_intrusion`
  boolean by checking whether the predicted class is anything other than
  `BENIGN`, so both views are available: "is this an attack" and "what kind."
- **Rare classes**: CICIDS2017 has a long tail of attack subtypes with only
  a handful of rows each (e.g. Heartbleed, Infiltration). `train_model.py`
  automatically collapses any class with fewer than 20 rows into an
  "Other Attack" bucket so the model isn't asked to learn a class from a
  handful of examples. Adjust `MIN_CLASS_COUNT` in `train_model.py` if you
  want a different cutoff.
- **Features**: 24 flow-level statistics (timing, packet volume, packet
  size, byte/packet rates, TCP flag counts) selected from CICIDS2017's ~80
  CICFlowMeter columns — enough to be a genuinely usable web form while
  still capturing most of the signal. Edit `backend/features.py` to change
  the feature set; `train_model.py` and `app.py` both read from that one
  file.
- **Model**: `RandomForestClassifier(n_estimators=250, class_weight="balanced")`
  with a `StandardScaler` on the inputs and a `LabelEncoder` over class
  names. Simple, fast to train, and reasonably robust to CICIDS2017's class
  imbalance (~80% benign traffic, uneven attack subtypes).
- **What `/api/predict` returns**: the predicted class name (`attack_type`),
  a binary `prediction`/`is_intrusion` view, an overall `confidence` (the
  winning class's probability), and a full `probabilities` breakdown across
  every class the model knows about — that's what powers the multi-bar
  chart in the UI.

## Notes & limitations

- The bundled synthetic dataset exists only so the pipeline runs without a
  6GB download — it is *not* a substitute for the real CICIDS2017 data, and
  a model trained on it will look unrealistically perfect (see the 100%
  metrics on first run). Train on the real CSVs before trusting any output.
- This is a demo/teaching project, not a production IDS. Real intrusion
  detection needs live packet capture (e.g. CICFlowMeter or Zeek) to
  compute these flow features from actual traffic, continuous retraining,
  and much more validation than a single held-out split.
#   i n t u t i o n - d e t e c t i o n - s y s t e m  
 