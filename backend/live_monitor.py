"""
Live traffic monitoring: groups packets into bidirectional flows, closes a
flow after a period of inactivity, and computes the same 24 CICFlowMeter-
style features the model was trained on — so live traffic can be scored by
the exact same model as the CSV/manual paths.

Two modes:
  - "capture": sniffs real packets with scapy. Requires scapy + (on Windows)
    Npcap installed, and admin/root privileges to open a raw socket.
  - "simulate": generates realistic-looking flows on a timer, no special
    permissions needed. This is the default and works everywhere, so the
    Live Monitor tab is usable immediately without any OS-level setup.

NOTE: this is a simplified, best-effort approximation of CICFlowMeter's
flow features (e.g. no active/idle sub-flow splitting), good enough for a
live demo — not a drop-in replacement for offline CICFlowMeter exports.
"""
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, List, Optional

import numpy as np

from features import FEATURES, FEATURE_ORDER

try:
    from scapy.all import AsyncSniffer, IP, TCP, UDP, get_if_list

    SCAPY_AVAILABLE = True
except Exception:
    SCAPY_AVAILABLE = False

FLOW_TIMEOUT = 2.0  # seconds of inactivity before a flow is considered "finished"
SWEEP_INTERVAL = 0.5


@dataclass
class Flow:
    key: tuple
    initiator: tuple
    timestamps: List[float] = field(default_factory=list)
    lengths: List[float] = field(default_factory=list)
    directions: List[str] = field(default_factory=list)
    flags: List[str] = field(default_factory=list)
    header_lens: List[float] = field(default_factory=list)
    last_seen: float = 0.0

    def add(self, ts, length, direction, flags, header_len):
        self.timestamps.append(ts)
        self.lengths.append(length)
        self.directions.append(direction)
        self.flags.append(flags)
        self.header_lens.append(header_len)
        self.last_seen = ts


def _flow_key(pkt):
    ip = pkt[IP]
    proto = ip.proto
    if TCP in pkt:
        sport, dport = pkt[TCP].sport, pkt[TCP].dport
    elif UDP in pkt:
        sport, dport = pkt[UDP].sport, pkt[UDP].dport
    else:
        return None
    a = (ip.src, sport)
    b = (ip.dst, dport)
    key = tuple(sorted([a, b])) + (proto,)
    return key, a


class FlowTracker:
    """Groups incoming packets into flows keyed by the 5-tuple, ignoring direction."""

    def __init__(self):
        self.flows = {}
        self.lock = threading.Lock()

    def handle_packet(self, pkt):
        if IP not in pkt or (TCP not in pkt and UDP not in pkt):
            return
        parsed = _flow_key(pkt)
        if parsed is None:
            return
        key, src = parsed
        ts = float(pkt.time)
        length = len(pkt)
        header_len = (pkt[IP].ihl * 4) + (pkt[TCP].dataofs * 4 if TCP in pkt else 8)
        flags = str(pkt[TCP].flags) if TCP in pkt else ""

        with self.lock:
            flow = self.flows.get(key)
            if flow is None:
                flow = Flow(key=key, initiator=src)
                self.flows[key] = flow
            direction = "fwd" if src == flow.initiator else "bwd"
            flow.add(ts, length, direction, flags, header_len)

    def sweep_expired(self) -> List[Flow]:
        now = time.time()
        finished = []
        with self.lock:
            expired_keys = [k for k, f in self.flows.items() if now - f.last_seen > FLOW_TIMEOUT]
            for k in expired_keys:
                finished.append(self.flows.pop(k))
        return finished


def compute_features(flow: Flow) -> dict:
    ts = np.array(flow.timestamps)
    lens = np.array(flow.lengths, dtype=float)
    dirs = np.array(flow.directions)
    header_lens = np.array(flow.header_lens, dtype=float)
    flags_list = flow.flags

    order = np.argsort(ts)
    ts, lens, dirs, header_lens = ts[order], lens[order], dirs[order], header_lens[order]
    flags_list = [flags_list[i] for i in order]
    flags_joined = "".join(flags_list)

    duration_s = max(float(ts[-1] - ts[0]), 1e-6)
    fwd_mask = dirs == "fwd"
    bwd_mask = dirs == "bwd"
    fwd_lens, bwd_lens = lens[fwd_mask], lens[bwd_mask]
    fwd_ts, bwd_ts = ts[fwd_mask], ts[bwd_mask]

    def iat_mean(arr):
        return float(np.mean(np.diff(arr)) * 1e6) if len(arr) > 1 else 0.0

    def iat_std(arr):
        return float(np.std(np.diff(arr)) * 1e6) if len(arr) > 1 else 0.0

    total_bytes = float(lens.sum())
    n_packets = len(lens)
    n_fwd, n_bwd = int(fwd_mask.sum()), int(bwd_mask.sum())

    feats = {
        "Flow Duration": duration_s * 1e6,
        "Total Fwd Packets": float(n_fwd),
        "Total Backward Packets": float(n_bwd),
        "Total Length of Fwd Packets": float(fwd_lens.sum()),
        "Total Length of Bwd Packets": float(bwd_lens.sum()),
        "Fwd Packet Length Max": float(fwd_lens.max()) if n_fwd else 0.0,
        "Fwd Packet Length Mean": float(fwd_lens.mean()) if n_fwd else 0.0,
        "Bwd Packet Length Max": float(bwd_lens.max()) if n_bwd else 0.0,
        "Bwd Packet Length Mean": float(bwd_lens.mean()) if n_bwd else 0.0,
        "Flow Bytes/s": total_bytes / duration_s,
        "Flow Packets/s": n_packets / duration_s,
        "Flow IAT Mean": iat_mean(ts),
        "Flow IAT Std": iat_std(ts),
        "Fwd IAT Mean": iat_mean(fwd_ts),
        "Bwd IAT Mean": iat_mean(bwd_ts),
        "Fwd PSH Flags": float(sum("P" in f for f, d in zip(flags_list, dirs) if d == "fwd")),
        "SYN Flag Count": float(flags_joined.count("S")),
        "RST Flag Count": float(flags_joined.count("R")),
        "PSH Flag Count": float(flags_joined.count("P")),
        "ACK Flag Count": float(flags_joined.count("A")),
        "Average Packet Size": float(lens.mean()) if n_packets else 0.0,
        "Down/Up Ratio": float(n_bwd / n_fwd) if n_fwd else 0.0,
        "Fwd Header Length": float(header_lens[fwd_mask].sum()) if n_fwd else 0.0,
        "Bwd Header Length": float(header_lens[bwd_mask].sum()) if n_bwd else 0.0,
        "Subflow Fwd Bytes": float(fwd_lens.sum()),
    }
    return {k: feats[k] for k in FEATURE_ORDER}


def simulate_one_flow(rng: np.random.Generator) -> dict:
    """Draws one plausible flow's features from the same example values used
    elsewhere in the app, with random jitter — used by simulate mode."""
    is_attack = rng.random() < 0.18
    idx = 3 if is_attack else 2
    out = {}
    for key, tup in FEATURES.items():
        base = tup[idx]
        jittered = base * float(1 + rng.normal(0, 0.18))
        out[key] = max(jittered, 0.0)
    return out


class LiveEngine:
    """Owns the background capture/simulate thread and pushes each finished
    flow's prediction out through a broadcast callback (set by the FastAPI
    app so results can be pushed over a websocket)."""

    def __init__(self, predict_fn: Callable[[dict], "PredictResult"]):
        self.predict_fn = predict_fn
        self.broadcast_fn: Optional[Callable[[dict], None]] = None
        self.mode = None
        self.interface = None
        self.running = False
        self._stop_event = threading.Event()
        self._threads: List[threading.Thread] = []
        self.sniffer = None
        self.stats = {"total": 0, "intrusions": 0, "started_at": None}

    def set_broadcast(self, fn: Callable[[dict], None]):
        self.broadcast_fn = fn

    def available_interfaces(self) -> List[str]:
        if not SCAPY_AVAILABLE:
            return []
        try:
            return get_if_list()
        except Exception:
            return []

    def start(self, mode: str = "simulate", interface: Optional[str] = None):
        if self.running:
            raise RuntimeError("Live monitoring is already running. Stop it first.")
        if mode == "capture" and not SCAPY_AVAILABLE:
            raise RuntimeError(
                "scapy is not available in this environment. Install it "
                "(`pip install scapy`) and, on Windows, install Npcap "
                "(https://npcap.com), then run the backend as Administrator. "
                "Use simulate mode if you just want to see the dashboard work."
            )

        self.mode = mode
        self.interface = interface
        self._stop_event.clear()
        self.stats = {"total": 0, "intrusions": 0, "started_at": time.strftime("%Y-%m-%d %H:%M:%S")}
        self.running = True

        if mode == "capture":
            tracker = FlowTracker()
            self.sniffer = AsyncSniffer(iface=interface or None, prn=tracker.handle_packet, store=False)
            self.sniffer.start()

            def sweep_loop():
                while not self._stop_event.is_set():
                    for flow in tracker.sweep_expired():
                        if len(flow.timestamps) < 2:
                            continue
                        self._emit(compute_features(flow))
                    time.sleep(SWEEP_INTERVAL)

            t = threading.Thread(target=sweep_loop, daemon=True)
            t.start()
            self._threads.append(t)
        else:
            rng = np.random.default_rng()

            def sim_loop():
                while not self._stop_event.is_set():
                    self._emit(simulate_one_flow(rng))
                    time.sleep(float(rng.uniform(0.5, 1.6)))

            t = threading.Thread(target=sim_loop, daemon=True)
            t.start()
            self._threads.append(t)

    def _emit(self, feature_dict: dict):
        result = self.predict_fn(feature_dict)
        self.stats["total"] += 1
        if result.is_intrusion:
            self.stats["intrusions"] += 1

        payload = {
            "features": feature_dict,
            "prediction": result.prediction,
            "is_intrusion": result.is_intrusion,
            "attack_type": getattr(result, "attack_type", None),
            "confidence": result.confidence,
            "probabilities": result.probabilities,
            "timestamp": time.strftime("%H:%M:%S"),
            "stats": dict(self.stats),
        }
        if self.broadcast_fn:
            self.broadcast_fn(payload)

    def stop(self):
        self._stop_event.set()
        if self.sniffer is not None:
            try:
                self.sniffer.stop()
            except Exception:
                pass
            self.sniffer = None
        self.running = False

    def status(self) -> dict:
        return {
            "running": self.running,
            "mode": self.mode,
            "interface": self.interface,
            "scapy_available": SCAPY_AVAILABLE,
            "stats": self.stats,
        }
