"""
FastAPI backend serving the CICIDS2017 intrusion-detection model.

Run with:
    uvicorn app:app --reload --port 5000
(or just: python app.py)

Interactive API docs are auto-generated at http://localhost:5000/docs

Endpoints:
  GET    /api/health          -> model status + evaluation metrics
  GET    /api/features         -> feature schema the frontend uses to build its form
  GET    /api/samples           -> example benign + attack payloads
  POST   /api/predict             -> single-flow prediction
  POST   /api/predict/batch        -> multi-flow prediction from a JSON array
  POST   /api/predict/csv            -> multi-flow prediction from an uploaded CSV
  GET    /api/insights                -> feature importances + confusion matrix
  GET    /api/history                   -> most recent predictions made this server session
  DELETE /api/history                     -> clear prediction history
  GET    /api/live/interfaces              -> network interfaces available for capture
  GET    /api/live/status                   -> is live monitoring running, and stats
  POST   /api/live/start                     -> start live monitoring (simulate or capture)
  POST   /api/live/stop                       -> stop live monitoring
  WS     /ws/live                              -> streams each newly-scored flow in real time
"""
import asyncio
import io
import json
import os
import time
import uuid
from pathlib import Path
from typing import Dict, List, Optional

import joblib
import numpy as np
import pandas as pd
from fastapi import (
    FastAPI,
    File,
    HTTPException,
    UploadFile,
    WebSocket,
    WebSocketDisconnect,
)
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, create_model

from features import FEATURES, FEATURE_ORDER, BENIGN_LABEL
from live_monitor import LiveEngine

MODEL_DIR = Path(__file__).parent / "model"
MAX_HISTORY = 50

# Comma-separated list of allowed frontend origins, e.g.:
#   ALLOWED_ORIGINS=https://frontend-eight-red-79.vercel.app,http://localhost:5173
# Defaults to "*" (allow everything) so local dev works with zero config —
# tighten this to your real frontend URL(s) once you deploy.
_allowed_origins_env = os.environ.get("ALLOWED_ORIGINS", "*")
ALLOWED_ORIGINS = (
    ["*"] if _allowed_origins_env.strip() == "*"
    else [o.strip() for o in _allowed_origins_env.split(",") if o.strip()]
)

app = FastAPI(
    title="FlowGuard IDS API",
    description="Serves predictions from a CICIDS2017-trained intrusion detection model.",
    version="2.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_methods=["*"],
    allow_headers=["*"],
)

_model = None
_scaler = None
_metadata = None
_encoder = None
_history: List[dict] = []  # newest first, in-memory only (resets on server restart)

# Build a Pydantic model dynamically from FEATURE_ORDER so every field is
# validated as a proper float with a helpful error message per-field.
FlowFeatures = create_model(
    "FlowFeatures",
    **{key: (float, Field(..., description=FEATURES[key][0])) for key in FEATURE_ORDER},
)


class PredictRequest(BaseModel):
    features: FlowFeatures


class PredictResult(BaseModel):
    prediction: str
    is_intrusion: bool
    attack_type: str
    confidence: float
    probabilities: Dict[str, float]


class BatchPredictRequest(BaseModel):
    flows: List[FlowFeatures]


def load_artifacts():
    global _model, _scaler, _metadata, _encoder
    if _model is None:
        if not (MODEL_DIR / "model.pkl").exists():
            raise RuntimeError("No trained model found. Run `python train_model.py` first.")
        _model = joblib.load(MODEL_DIR / "model.pkl")
        _scaler = joblib.load(MODEL_DIR / "scaler.pkl")
        _encoder = joblib.load(MODEL_DIR / "label_encoder.pkl")
        with open(MODEL_DIR / "metadata.json") as f:
            _metadata = json.load(f)
    return _model, _scaler, _metadata, _encoder


def run_prediction(feature_dict: dict) -> PredictResult:
    model, scaler, _, encoder = load_artifacts()
    row = [float(feature_dict[k]) for k in FEATURE_ORDER]
    X_scaled = scaler.transform(np.array(row).reshape(1, -1))

    pred_idx = int(model.predict(X_scaled)[0])
    proba = model.predict_proba(X_scaled)[0]  # one probability per class
    class_names = list(encoder.classes_)
    attack_type = class_names[pred_idx]
    is_intrusion = attack_type != BENIGN_LABEL

    return PredictResult(
        prediction="INTRUSION" if is_intrusion else "NORMAL",
        is_intrusion=is_intrusion,
        attack_type=attack_type,
        confidence=float(proba[pred_idx]),
        probabilities={name: float(p) for name, p in zip(class_names, proba)},
    )


def record_history(feature_dict: dict, result: PredictResult, source: str):
    _history.insert(
        0,
        {
            "id": str(uuid.uuid4())[:8],
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "source": source,
            "prediction": result.prediction,
            "attack_type": result.attack_type,
            "confidence": round(result.confidence, 4),
            "flow_duration": feature_dict.get("Flow Duration"),
            "total_fwd_packets": feature_dict.get("Total Fwd Packets"),
        },
    )
    del _history[MAX_HISTORY:]


@app.get("/api/health")
def health():
    try:
        _, _, meta, _ = load_artifacts()
        return {
            "status": "ok",
            "model_loaded": True,
            "trained_at": meta.get("trained_at"),
            "metrics": meta.get("metrics"),
        }
    except Exception as e:
        raise HTTPException(status_code=503, detail=str(e))


@app.get("/api/features")
def get_features():
    return {
        "features": [
            {
                "key": key,
                "label": label,
                "unit": unit,
                "example_benign": benign_ex,
                "example_attack": attack_ex,
            }
            for key, (label, unit, benign_ex, attack_ex) in FEATURES.items()
        ]
    }


@app.get("/api/samples")
def get_samples():
    return {
        "benign": {k: v[2] for k, v in FEATURES.items()},
        "attack": {k: v[3] for k, v in FEATURES.items()},
    }


@app.post("/api/predict", response_model=PredictResult)
def predict(req: PredictRequest):
    feature_dict = req.features.model_dump()
    result = run_prediction(feature_dict)
    record_history(feature_dict, result, source="manual")
    return result


@app.post("/api/predict/batch")
def predict_batch(req: BatchPredictRequest):
    if not req.flows:
        raise HTTPException(status_code=400, detail="No flows provided.")
    results = []
    for flow in req.flows:
        feature_dict = flow.model_dump()
        result = run_prediction(feature_dict)
        record_history(feature_dict, result, source="batch-json")
        results.append(result)
    n_intrusion = sum(r.is_intrusion for r in results)
    return {
        "results": results,
        "summary": {
            "total": len(results),
            "intrusions": n_intrusion,
            "normal": len(results) - n_intrusion,
        },
    }


@app.post("/api/predict/csv")
async def predict_csv(file: UploadFile = File(...)):
    if not file.filename.lower().endswith(".csv"):
        raise HTTPException(status_code=400, detail="Please upload a .csv file.")

    raw = await file.read()
    try:
        df = pd.read_csv(io.StringIO(raw.decode("utf-8", errors="replace")))
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Could not parse CSV: {e}")

    df.columns = [c.strip() for c in df.columns]
    missing = [c for c in FEATURE_ORDER if c not in df.columns]
    if missing:
        raise HTTPException(
            status_code=400,
            detail=f"CSV is missing required columns: {missing[:6]}"
            + (" ..." if len(missing) > 6 else ""),
        )

    df = df[FEATURE_ORDER].apply(pd.to_numeric, errors="coerce")
    bad_rows = int(df.isna().any(axis=1).sum())
    df = df.dropna()
    if df.empty:
        raise HTTPException(status_code=400, detail="No valid numeric rows found in CSV.")

    results = []
    for _, row in df.iterrows():
        feature_dict = row.to_dict()
        result = run_prediction(feature_dict)
        record_history(feature_dict, result, source=f"csv:{file.filename}")
        results.append(result.model_dump())

    n_intrusion = sum(r["is_intrusion"] for r in results)
    return {
        "results": results,
        "summary": {
            "total": len(results),
            "intrusions": n_intrusion,
            "normal": len(results) - n_intrusion,
            "skipped_invalid_rows": bad_rows,
        },
    }


@app.get("/api/insights")
def insights():
    _, _, meta, _ = load_artifacts()
    importances = meta.get("feature_importances", {})
    top = sorted(importances.items(), key=lambda kv: -kv[1])[:12]
    return {
        "metrics": meta.get("metrics"),
        "top_features": [{"feature": k, "importance": v} for k, v in top],
        "trained_at": meta.get("trained_at"),
    }


@app.get("/api/history")
def get_history():
    return {"history": _history}


@app.delete("/api/history")
def clear_history():
    _history.clear()
    return {"cleared": True}


# ---------------------------------------------------------------------------
# Live monitoring (simulate or real packet capture) streamed over websocket
# ---------------------------------------------------------------------------

live_engine = LiveEngine(predict_fn=lambda feats: _predict_and_record_live(feats))


def _predict_and_record_live(feature_dict: dict) -> "PredictResult":
    result = run_prediction(feature_dict)
    record_history(feature_dict, result, source=f"live-{live_engine.mode or 'unknown'}")
    return result


class ConnectionManager:
    def __init__(self):
        self.active: List[WebSocket] = []

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.active.append(ws)

    def disconnect(self, ws: WebSocket):
        if ws in self.active:
            self.active.remove(ws)

    async def broadcast(self, payload: dict):
        dead = []
        for ws in self.active:
            try:
                await ws.send_json(payload)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)


manager = ConnectionManager()


@app.on_event("startup")
async def on_startup():
    loop = asyncio.get_event_loop()

    def broadcast_threadsafe(payload: dict):
        asyncio.run_coroutine_threadsafe(manager.broadcast(payload), loop)

    live_engine.set_broadcast(broadcast_threadsafe)


class LiveStartRequest(BaseModel):
    mode: str = Field("simulate", description="'simulate' or 'capture'")
    interface: Optional[str] = Field(None, description="Network interface name, capture mode only")


@app.get("/api/live/interfaces")
def live_interfaces():
    return {"interfaces": live_engine.available_interfaces(), "scapy_available": live_engine.status()["scapy_available"]}


@app.get("/api/live/status")
def live_status():
    return live_engine.status()


@app.post("/api/live/start")
def live_start(req: LiveStartRequest):
    try:
        live_engine.start(mode=req.mode, interface=req.interface)
    except RuntimeError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return live_engine.status()


@app.post("/api/live/stop")
def live_stop():
    live_engine.stop()
    return live_engine.status()


@app.websocket("/ws/live")
async def ws_live(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            # We don't expect incoming messages, but reading keeps the
            # connection alive and lets us detect disconnects promptly.
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)


if __name__ == "__main__":
    import uvicorn

    load_artifacts()  # fail fast if model isn't trained yet
    uvicorn.run("app:app", host="0.0.0.0", port=5000, reload=True)
